from collections import Counter
from include.TCPFlowObject import TCPFlowObject
from include.TsharkExtraction import TSharkExtraction


class TCPStreamCatcher:
    """Used for extracting and aggregating TCP stream information from a network capture."""

    def __init__(
        self,
        pcap_path,
        tshark_bin="tshark",
        resolve_ip_info=True,
        ip_lookup_timeout=3,
        max_payload_samples=3,
        payload_preview_bytes=32,
    ):
        """Object constructor for the TCP stream extractor"""
        self.trace_path = pcap_path
        self.tshark_bin = tshark_bin
        self.resolve_ip_info = resolve_ip_info
        self.ip_lookup_timeout = ip_lookup_timeout
        self.max_payload_samples = max_payload_samples
        self.payload_preview_bytes = payload_preview_bytes

        self.flows = {}
        self.dns_map = {}

    def catch_streams(self):
        """Extracts passive DNS and TCP packets from the PCAP and populates TCPFlowObject instances."""
        extractor = TSharkExtraction(self.trace_path, tshark_bin=self.tshark_bin)
        self.dns_map = extractor.extract_dns_map()
        records = extractor.extract_info()

        for pkt in records:
            stream_id = pkt.get("tcp.stream")
            if stream_id is None or stream_id == "":
                continue

            if stream_id not in self.flows:
                self.flows[stream_id] = TCPFlowObject(stream_id)

            flow = self.flows[stream_id]
            src_ip = pkt.get("ip.src") or pkt.get("ipv6.src")
            dst_ip = pkt.get("ip.dst") or pkt.get("ipv6.dst")

            flow.add_packet(
                timestamp=pkt.get("frame.time_epoch"),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=pkt.get("tcp.srcport"),
                dst_port=pkt.get("tcp.dstport"),
                frame_len=pkt.get("frame.len") or 0,
                tcp_len=pkt.get("tcp.len") or 0,
                syn_flag=pkt.get("tcp.flags.syn"),
                ack_flag=pkt.get("tcp.flags.ack"),
                protocol=pkt.get("frame.protocols"),
                sni=pkt.get("tls.handshake.extensions_server_name"),
                alpn=pkt.get("tls.handshake.extensions_alpn_str"),
                tls_ver=pkt.get("tls.handshake.version"),
                tls_sup_ver=pkt.get("tls.handshake.extensions.supported_version"),
                ja3=pkt.get("tls.handshake.ja3"),
                cert_utf8=pkt.get("x509sat.uTF8String"),
                cert_print=pkt.get("x509sat.printableString"),
                http_host=pkt.get("http.host"),
                http_uri=pkt.get("http.request.uri"),
                http_ua=pkt.get("http.user_agent"),
                payload_hex=pkt.get("tcp.payload"),
                max_payload_samples=self.max_payload_samples,
                payload_preview_bytes=self.payload_preview_bytes,
            )

        # Enrich flows with passive DNS and IP intelligence
        for flow in self.flows.values():
            if flow.src_ip and flow.src_ip in self.dns_map:
                flow.src_fqdn = self.dns_map[flow.src_ip]
            if flow.dst_ip and flow.dst_ip in self.dns_map:
                flow.dst_fqdn = self.dns_map[flow.dst_ip]

            if flow.src_ip:
                flow.src_attributes = TCPFlowObject.get_ip_info(
                    flow.src_ip,
                    timeout=self.ip_lookup_timeout,
                    allow_external=self.resolve_ip_info,
                )
            if flow.dst_ip:
                flow.dst_attributes = TCPFlowObject.get_ip_info(
                    flow.dst_ip,
                    timeout=self.ip_lookup_timeout,
                    allow_external=self.resolve_ip_info,
                )

        return self.flows

    def find_unknown_patterns(self):
        """Analyzes flows where no standard L7 protocol was identified to assist IDS/DPI signature creation."""
        unknown_flows = [f for f in self.flows.values() if f.is_unknown_traffic]
        magic_counter = Counter()
        port_counter = Counter()
        ascii_prefix_counter = Counter()

        for flow in unknown_flows:
            if flow.dst_port:
                port_counter[flow.dst_port] += 1
            if flow.payload_samples:
                first_sample = flow.payload_samples[0]
                magic = first_sample.get("magic_4bytes")
                if magic:
                    magic_counter[magic] += 1
                ascii_pref = first_sample.get("ascii_prefix", "")[:8]
                if ascii_pref:
                    ascii_prefix_counter[ascii_pref] += 1

        return {
            "unknown_flow_count": len(unknown_flows),
            "unknown_flow_ids": [f.flow_id for f in unknown_flows],
            "recurring_magic_4bytes": dict(magic_counter.most_common(10)),
            "recurring_dst_ports": dict(port_counter.most_common(10)),
            "recurring_ascii_prefixes": dict(ascii_prefix_counter.most_common(10)),
        }
