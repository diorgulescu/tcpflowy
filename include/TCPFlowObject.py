from collections import Counter
import ipaddress
import json
import math
import socket
import subprocess
import urllib.error
import urllib.request


# Well-known port fallback hints when application protocol is not explicitly dissected
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS/TLS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "AMQP",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

TLS_VERSION_MAP = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# Known OS, Browser Telemetry, Captive Portal, and Certificate Revocation noise patterns
NOISE_DOMAIN_PATTERNS = (
    "gvt1.com",
    "gvt2.com",
    "safebrowsing.googleapis.com",
    "clientservices.googleapis.com",
    "update.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "content-autofill.googleapis.com",
    "accounts.google.com",
    "ocsp.",
    "crl.",
    "digicert.com",
    "letsencrypt.org",
    "sectigo.com",
    "identrust.com",
    "globalsign.com",
    "detectportal.firefox.com",
    "aus5.mozilla.org",
    "telemetry.mozilla.org",
    "normandy.cdn.mozilla.net",
    "location.services.mozilla.com",
    "shavar.services.mozilla.com",
    "configuration.apple.com",
    "gspe1-ssl.ls.apple.com",
    "init.ess.apple.com",
    "xp.apple.com",
    "mesu.apple.com",
    "captive.apple.com",
    "time.apple.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "windowsupdate.com",
    "events.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "login.live.com",
    "smartscreen.microsoft.com",
    "doubleclick.net",
    "googlesyndication.com",
    "google-analytics.com",
)


class TCPFlowObject:
    """Represents a flow that has been extracted from a provided network capture.
    This is instantiated each time a new flow is detected, and further associated
    data that has been extracted will get added to the instance. It also creates
    a global registry in which flows will be stored."""

    # Global registry mapping flow_id (str/int) -> TCPFlowObject
    flows_registry = {}
    # Cache for IP intelligence lookups across flows to avoid duplicate requests
    _ip_cache = {}

    def __init__(self, flow_id):
        """Object constructor, requiring only the tcp stream number"""
        self.flow_id = str(flow_id)
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.src_fqdn = None
        self.dst_fqdn = None
        self.src_attributes = {}
        self.dst_attributes = {}

        # Traffic metrics & timestamps
        self.packet_count = 0
        self.total_bytes = 0
        self.payload_bytes = 0
        self.first_seen = None
        self.last_seen = None

        # Directional metrics (Client -> Server vs. Server -> Client)
        self._endpoint_oriented = False
        self.c2s_packets = 0
        self.c2s_bytes = 0
        self.c2s_payload_bytes = 0
        self.s2c_packets = 0
        self.s2c_bytes = 0
        self.s2c_payload_bytes = 0

        # Protocol & DPI metadata
        self.protocols = []
        self.sni_list = []
        self.alpn_list = []
        self.tls_versions = []
        self.ja3_list = []
        self.cert_subjects = []
        self.http_hosts = []
        self.http_uris = []
        self.http_user_agents = []

        # Payload inspection & entropy buffer
        self.payload_samples = []  # Combined samples with direction
        self.c2s_payload_samples = []
        self.s2c_payload_samples = []
        self._entropy_buffer = bytearray()

        # Register flow in the class-level dictionary
        TCPFlowObject.flows_registry[self.flow_id] = self

    @classmethod
    def clear_registry(cls):
        """Clears the global flow registry."""
        cls.flows_registry.clear()

    @classmethod
    def getFlowIDBySourceIP(cls, ip_src_to_search, flows=None):
        """Returns the flow ID(s) that have the specified IP source"""
        target_flows = flows if flows is not None else cls.flows_registry
        return [
            str(fid)
            for fid, flow in target_flows.items()
            if flow.src_ip == ip_src_to_search
        ]

    @classmethod
    def getFlowIDByDestIP(cls, ip_dst_to_search, flows=None):
        """Returns the flow ID(s) that contain the specified IP destination"""
        target_flows = flows if flows is not None else cls.flows_registry
        return [
            str(fid)
            for fid, flow in target_flows.items()
            if flow.dst_ip == ip_dst_to_search
        ]

    @property
    def duration(self):
        """Returns flow duration in seconds."""
        if self.first_seen is not None and self.last_seen is not None:
            return max(0.0, round(self.last_seen - self.first_seen, 6))
        return 0.0

    @property
    def primary_domain(self):
        """Returns the best known domain/hostname associated with the destination."""
        if self.sni_list:
            return self.sni_list[0]
        if self.http_hosts:
            return self.http_hosts[0]
        if self.dst_fqdn:
            return self.dst_fqdn
        if self.cert_subjects:
            return self.cert_subjects[0]
        if self.dst_attributes and self.dst_attributes.get("reverse"):
            return self.dst_attributes["reverse"]
        return None

    @property
    def tls_version(self):
        """Returns the highest negotiated/advertised TLS version string."""
        if not self.tls_versions:
            return None
        if "TLS 1.3" in self.tls_versions:
            return "TLS 1.3"
        return self.tls_versions[-1]

    @property
    def detected_application(self):
        """Infers the application/protocol classification for DPI/IDS triage."""
        high_level = [
            p for p in self.protocols
            if p.upper() not in ("ETH", "ETHERTYPE", "IP", "IPV6", "TCP", "DATA", "SLL", "NULL", "RAW", "PKTAP")
        ]
        if self.sni_list or self.ja3_list or "tls" in [p.lower() for p in high_level]:
            ver = self.tls_version or "TLS"
            if self.alpn_list:
                return f"{ver} ({self.alpn_list[0]})"
            return ver
        if self.http_hosts or "http" in [p.lower() for p in high_level]:
            return "HTTP"
        if high_level:
            return high_level[-1].upper()
        if self.dst_port and int(self.dst_port) in WELL_KNOWN_PORTS:
            return f"{WELL_KNOWN_PORTS[int(self.dst_port)]} (:{self.dst_port})"
        if self.src_port and int(self.src_port) in WELL_KNOWN_PORTS:
            return f"{WELL_KNOWN_PORTS[int(self.src_port)]} (:{self.src_port})"
        if self.payload_bytes > 0:
            return "UNKNOWN_TCP_PAYLOAD"
        return "TCP_HANDSHAKE_ONLY"

    @property
    def is_unknown_traffic(self):
        """Returns True if the flow carries payload data but no L7 protocol was identified by tshark."""
        high_level = [
            p for p in self.protocols
            if p.upper() not in ("ETH", "ETHERTYPE", "IP", "IPV6", "TCP", "DATA", "SLL", "NULL", "RAW", "PKTAP")
        ]
        return (
            self.payload_bytes > 0
            and len(high_level) == 0
            and not self.sni_list
            and not self.http_hosts
            and not self.ja3_list
        )

    @property
    def payload_entropy(self):
        """Calculates Shannon entropy (0.0 to 8.0 bits/byte) on the buffered flow payload."""
        if not self._entropy_buffer:
            return None
        total = len(self._entropy_buffer)
        counts = Counter(self._entropy_buffer)
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
        return round(entropy, 2)

    @property
    def entropy_profile(self):
        """Classifies payload entropy to help engineers distinguish plaintext/structured binary from encrypted data."""
        ent = self.payload_entropy
        if ent is None:
            return "NO_PAYLOAD"
        if ent < 5.0:
            return "PLAINTEXT/ASCII"
        if ent <= 6.8:
            return "STRUCTURED_BINARY"
        return "ENCRYPTED/COMPRESSED"

    @property
    def direction_profile(self):
        """Summarizes directional flow behavior (Upload vs Download vs Balanced)."""
        if self.payload_bytes == 0:
            return "HANDSHAKE_ONLY"
        if self.c2s_payload_bytes > 0 and self.s2c_payload_bytes == 0:
            return "C->S ONLY"
        if self.s2c_payload_bytes > 0 and self.c2s_payload_bytes == 0:
            return "S->C ONLY"
        if self.c2s_payload_bytes > self.s2c_payload_bytes * 2.5:
            return "UPLOAD-HEAVY"
        if self.s2c_payload_bytes > self.c2s_payload_bytes * 2.5:
            return "DOWNLOAD-HEAVY"
        return "BIDIRECTIONAL"

    @property
    def noise_reason(self):
        """Returns the reason if this flow matches known OS/Browser telemetry or OCSP/CRL background noise."""
        candidates = [
            self.primary_domain,
            self.dst_fqdn,
            *(self.sni_list or []),
            *(self.http_hosts or []),
        ]
        for dom in candidates:
            if not dom:
                continue
            dom_low = dom.lower()
            for pat in NOISE_DOMAIN_PATTERNS:
                if pat in dom_low:
                    return f"Background/Telemetry domain ({pat})"
        for ua in self.http_user_agents:
            ua_low = ua.lower()
            if any(k in ua_low for k in ("microsoft-cryptoapi", "ocsp", "trustd", "cfnetwork")):
                return f"OS Background User-Agent ({ua[:28]})"
        return None

    @property
    def is_background_noise(self):
        """Returns True if the flow is recognized as background OS/Browser/OCSP noise."""
        return self.noise_reason is not None

    def _orient_endpoints(self, pkt_src_ip, pkt_dst_ip, pkt_src_port, pkt_dst_port, is_syn, is_ack):
        """Ensures src_ip:src_port represents the Client and dst_ip:dst_port represents the Server."""
        s_port = int(pkt_src_port) if pkt_src_port and str(pkt_src_port).isdigit() else pkt_src_port
        d_port = int(pkt_dst_port) if pkt_dst_port and str(pkt_dst_port).isdigit() else pkt_dst_port

        # Definitive SYN (client initiating connection)
        if is_syn and not is_ack:
            self.src_ip, self.src_port = pkt_src_ip, s_port
            self.dst_ip, self.dst_port = pkt_dst_ip, d_port
            self._endpoint_oriented = True
            return

        # Definitive SYN-ACK (server responding to client)
        if is_syn and is_ack:
            self.src_ip, self.src_port = pkt_dst_ip, d_port
            self.dst_ip, self.dst_port = pkt_src_ip, s_port
            self._endpoint_oriented = True
            return

        # First packet seen in a mid-stream capture: use port heuristics
        if self.src_ip is None and pkt_src_ip:
            if isinstance(s_port, int) and isinstance(d_port, int):
                if s_port in WELL_KNOWN_PORTS and d_port not in WELL_KNOWN_PORTS:
                    self.src_ip, self.src_port = pkt_dst_ip, d_port
                    self.dst_ip, self.dst_port = pkt_src_ip, s_port
                    self._endpoint_oriented = True
                    return
                if s_port < 1024 and d_port >= 1024:
                    self.src_ip, self.src_port = pkt_dst_ip, d_port
                    self.dst_ip, self.dst_port = pkt_src_ip, s_port
                    self._endpoint_oriented = True
                    return
            self.src_ip, self.src_port = pkt_src_ip, s_port
            self.dst_ip, self.dst_port = pkt_dst_ip, d_port
            self._endpoint_oriented = True

    def add_packet(
        self,
        timestamp=None,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        frame_len=0,
        tcp_len=0,
        syn_flag=None,
        ack_flag=None,
        protocol=None,
        sni=None,
        alpn=None,
        tls_ver=None,
        tls_sup_ver=None,
        ja3=None,
        cert_utf8=None,
        cert_print=None,
        http_host=None,
        http_uri=None,
        http_ua=None,
        payload_hex=None,
        max_payload_samples=3,
        payload_preview_bytes=32,
    ):
        """Aggregates information from a single packet belonging to this TCP stream."""
        is_syn = str(syn_flag).lower() in ("true", "1")
        is_ack = str(ack_flag).lower() in ("true", "1")

        if not self._endpoint_oriented or (is_syn and not is_ack):
            self._orient_endpoints(src_ip, dst_ip, src_port, dst_port, is_syn, is_ack)

        f_len = int(frame_len) if frame_len and str(frame_len).isdigit() else 0
        t_len = int(tcp_len) if tcp_len and str(tcp_len).isdigit() else 0

        self.packet_count += 1
        self.total_bytes += f_len
        self.payload_bytes += t_len

        # Determine packet direction relative to Client (self.src_ip:self.src_port)
        pkt_s_port = int(src_port) if src_port and str(src_port).isdigit() else src_port
        is_c2s = (src_ip == self.src_ip and pkt_s_port == self.src_port)
        direction_label = "C->S" if is_c2s else "S->C"

        if is_c2s:
            self.c2s_packets += 1
            self.c2s_bytes += f_len
            self.c2s_payload_bytes += t_len
        else:
            self.s2c_packets += 1
            self.s2c_bytes += f_len
            self.s2c_payload_bytes += t_len

        if timestamp is not None:
            try:
                ts = float(timestamp)
                if self.first_seen is None or ts < self.first_seen:
                    self.first_seen = ts
                if self.last_seen is None or ts > self.last_seen:
                    self.last_seen = ts
            except ValueError:
                pass

        if protocol:
            for proto in protocol.split(":"):
                proto_clean = proto.strip()
                if proto_clean and proto_clean not in self.protocols:
                    self.protocols.append(proto_clean)

        if sni:
            for item in sni.split(","):
                item_clean = item.strip()
                if item_clean and item_clean not in self.sni_list:
                    self.sni_list.append(item_clean)

        if alpn:
            for item in alpn.split(","):
                item_clean = item.strip()
                if item_clean and item_clean not in self.alpn_list:
                    self.alpn_list.append(item_clean)

        for raw_ver in (tls_sup_ver, tls_ver):
            if raw_ver:
                for v in raw_ver.split(","):
                    v_clean = v.strip().lower()
                    mapped = TLS_VERSION_MAP.get(v_clean)
                    if mapped and mapped not in self.tls_versions:
                        self.tls_versions.append(mapped)

        if ja3:
            for item in ja3.split(","):
                item_clean = item.strip()
                if item_clean and item_clean not in self.ja3_list:
                    self.ja3_list.append(item_clean)

        for cert_field in (cert_utf8, cert_print):
            if cert_field:
                for item in cert_field.split(","):
                    item_clean = item.strip()
                    if item_clean and "." in item_clean and " " not in item_clean:
                        if item_clean not in self.cert_subjects:
                            self.cert_subjects.append(item_clean)

        if http_host:
            for item in http_host.split(","):
                item_clean = item.strip()
                if item_clean and item_clean not in self.http_hosts:
                    self.http_hosts.append(item_clean)

        if http_uri:
            if http_uri not in self.http_uris and len(self.http_uris) < 10:
                self.http_uris.append(http_uri)

        if http_ua:
            if http_ua not in self.http_user_agents:
                self.http_user_agents.append(http_ua)

        if payload_hex:
            clean_hex = payload_hex.replace(":", "").strip()
            if clean_hex:
                try:
                    raw_bytes = bytes.fromhex(clean_hex)
                    # Add to entropy buffer (up to 4096 bytes per flow)
                    if len(self._entropy_buffer) < 4096:
                        rem = 4096 - len(self._entropy_buffer)
                        self._entropy_buffer.extend(raw_bytes[:rem])

                    preview_bytes = raw_bytes[:payload_preview_bytes]
                    sample_obj = {
                        "direction": direction_label,
                        "length": len(raw_bytes),
                        "raw_hex": preview_bytes.hex(),
                        "hex_prefix": preview_bytes.hex(" "),
                        "ascii_prefix": "".join(
                            chr(b) if 32 <= b <= 126 else "." for b in preview_bytes
                        ),
                        "magic_4bytes": raw_bytes[:4].hex(),
                    }

                    if len(self.payload_samples) < max_payload_samples:
                        self.payload_samples.append(sample_obj)
                    if is_c2s and len(self.c2s_payload_samples) < max_payload_samples:
                        self.c2s_payload_samples.append(sample_obj)
                    elif not is_c2s and len(self.s2c_payload_samples) < max_payload_samples:
                        self.s2c_payload_samples.append(sample_obj)
                except ValueError:
                    pass

    @classmethod
    def get_ip_info(cls, ip, timeout=3, allow_external=True):
        """Obtains WHOIS/GeoIP/ASN and reverse DNS information about the provided IP.
        Uses an in-memory cache, private IP check, reverse DNS, and ip-api.com JSON API
        (with fallback to ip-tracer if installed).
        Returns a dictionary containing all findings."""
        if not ip:
            return {}

        if ip in cls._ip_cache:
            return cls._ip_cache[ip]

        ip_info = {"ip": ip}

        try:
            addr = ipaddress.ip_address(ip)
            is_lan = (
                addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or (
                    addr.version == 4
                    and (
                        addr in ipaddress.IPv4Network("10.0.0.0/8")
                        or addr in ipaddress.IPv4Network("172.16.0.0/12")
                        or addr in ipaddress.IPv4Network("192.168.0.0/16")
                    )
                )
                or (addr.version == 6 and addr in ipaddress.IPv6Network("fc00::/7"))
            )
            if is_lan:
                ip_info["scope"] = "private/local"
                ip_info["org"] = "Local Network"
                ip_info["asn"] = "LOCAL"
                cls._ip_cache[ip] = ip_info
                return ip_info
            if addr.is_private:
                ip_info["scope"] = "reserved/test-net"
                cls._ip_cache[ip] = ip_info
                return ip_info
            ip_info["scope"] = "public"
        except ValueError:
            ip_info["scope"] = "unknown"

        if allow_external:
            try:
                host, _, _ = socket.gethostbyaddr(ip)
                ip_info["reverse"] = host
            except (socket.herror, socket.gaierror, OSError):
                pass

            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,reverse,query"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "tcpflowy/2.0"})
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    if data.get("status") == "success":
                        ip_info["country"] = data.get("country")
                        ip_info["countryCode"] = data.get("countryCode")
                        ip_info["city"] = data.get("city")
                        ip_info["isp"] = data.get("isp")
                        ip_info["org"] = data.get("org") or data.get("isp")
                        ip_info["asn"] = data.get("as")
                        if data.get("reverse") and not ip_info.get("reverse"):
                            ip_info["reverse"] = data.get("reverse")
                        cls._ip_cache[ip] = ip_info
                        return ip_info
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                pass

            try:
                rawdata = subprocess.run(
                    ["ip-tracer", "-t", ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
                if rawdata.returncode == 0 and rawdata.stdout:
                    text_buffer = rawdata.stdout.decode("utf-8", errors="ignore")
                    for ansi in ("\x1b[01;33m", "\x1b[01;37m", "\x1b[01;32m", "\x1b[00m"):
                        text_buffer = text_buffer.replace(ansi, "")
                    lines = [line for line in text_buffer.split("\n")[15:] if ">" in line]
                    for field in lines:
                        key, value = field.split(">", 1)
                        ip_info[key.strip()] = value.strip()
            except (FileNotFoundError, subprocess.SubprocessError, OSError):
                pass

        cls._ip_cache[ip] = ip_info
        return ip_info

    def to_dict(self):
        """Serializes the TCPFlowObject to a JSON-friendly dictionary."""
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "src_fqdn": self.src_fqdn,
            "dst_fqdn": self.dst_fqdn,
            "primary_domain": self.primary_domain,
            "detected_application": self.detected_application,
            "is_unknown_traffic": self.is_unknown_traffic,
            "is_background_noise": self.is_background_noise,
            "noise_reason": self.noise_reason,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "payload_bytes": self.payload_bytes,
            "c2s_packets": self.c2s_packets,
            "c2s_bytes": self.c2s_bytes,
            "c2s_payload_bytes": self.c2s_payload_bytes,
            "s2c_packets": self.s2c_packets,
            "s2c_bytes": self.s2c_bytes,
            "s2c_payload_bytes": self.s2c_payload_bytes,
            "direction_profile": self.direction_profile,
            "payload_entropy": self.payload_entropy,
            "entropy_profile": self.entropy_profile,
            "duration_sec": self.duration,
            "protocols": self.protocols,
            "sni_list": self.sni_list,
            "alpn_list": self.alpn_list,
            "tls_version": self.tls_version,
            "ja3_list": self.ja3_list,
            "cert_subjects": self.cert_subjects,
            "http_hosts": self.http_hosts,
            "http_uris": self.http_uris,
            "http_user_agents": self.http_user_agents,
            "payload_samples": self.payload_samples,
            "c2s_payload_samples": self.c2s_payload_samples,
            "s2c_payload_samples": self.s2c_payload_samples,
            "src_attributes": self.src_attributes,
            "dst_attributes": self.dst_attributes,
        }
