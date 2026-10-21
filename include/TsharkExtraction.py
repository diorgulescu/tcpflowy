import os
import shutil
import subprocess


class TSharkExtraction:
    """This class contains all required operations for extracting TCP stream/flow,
    TLS fingerprinting, and passive DNS information using tshark."""

    DEFAULT_FIELDS = [
        "tcp.stream",
        "frame.time_epoch",
        "ip.src",
        "ipv6.src",
        "tcp.srcport",
        "ip.dst",
        "ipv6.dst",
        "tcp.dstport",
        "frame.len",
        "tcp.len",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "frame.protocols",
        "tls.handshake.extensions_server_name",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.version",
        "tls.handshake.extensions.supported_version",
        "tls.handshake.ja3",
        "x509sat.uTF8String",
        "x509sat.printableString",
        "http.host",
        "http.request.uri",
        "http.user_agent",
        "tcp.payload",
    ]

    def __init__(self, pcap_path, attributes_to_extract=None, tshark_bin="tshark"):
        self.trace = pcap_path
        self.attributes = attributes_to_extract or self.DEFAULT_FIELDS
        self.tshark_bin = shutil.which(tshark_bin) or tshark_bin

    def _validate_environment(self):
        if not os.path.isfile(self.trace):
            raise FileNotFoundError(f"PCAP file not found: {self.trace}")
        if not shutil.which(self.tshark_bin):
            raise RuntimeError(
                f"'{self.tshark_bin}' binary was not found in PATH. Please install Wireshark/tshark."
            )

    def extract_dns_map(self):
        """Extracts passive DNS A/AAAA mappings (IP -> FQDN) from DNS responses in the PCAP."""
        self._validate_environment()
        cmd = [
            self.tshark_bin,
            "-r",
            self.trace,
            "-nn",
            "-Y",
            "dns.flags.response == 1 && (dns.a || dns.aaaa)",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "dns.qry.name",
            "-e",
            "dns.a",
            "-e",
            "dns.aaaa",
        ]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        dns_map = {}
        if result.returncode != 0:
            return dns_map

        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if not parts:
                continue
            qry_name = parts[0].split(",")[0].strip() if len(parts) > 0 else ""
            if not qry_name:
                continue
            ips_v4 = parts[1].split(",") if len(parts) > 1 and parts[1] else []
            ips_v6 = parts[2].split(",") if len(parts) > 2 and parts[2] else []
            for ip in ips_v4 + ips_v6:
                ip_clean = ip.strip()
                if ip_clean and ip_clean not in dns_map:
                    dns_map[ip_clean] = qry_name
        return dns_map

    def extract_info(self):
        """Runs tshark on the capture file and returns parsed packet dictionaries for all TCP packets."""
        self._validate_environment()
        cmd = [
            self.tshark_bin,
            "-r",
            self.trace,
            "-nn",
            "-Y",
            "tcp",
            "-T",
            "fields",
            "-E",
            "separator=\t",
        ]
        for field in self.attributes:
            cmd.extend(["-e", field])

        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False
        )
        if result.returncode != 0:
            err_msg = result.stderr.strip() or f"tshark exited with code {result.returncode}"
            raise RuntimeError(f"Error running tshark on '{self.trace}': {err_msg}")

        records = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            values = line.split("\t")
            record = {}
            for idx, attr in enumerate(self.attributes):
                record[attr] = values[idx].strip() if idx < len(values) else ""
            records.append(record)
        return records


# Alias for backward compatibility
TsharkExtraction = TSharkExtraction
