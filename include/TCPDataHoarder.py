from collections import Counter, defaultdict
import html
import json
import os
from include.TCPStreamCatcher import TCPStreamCatcher


class TCPDataHoarder:
    """Coordinates TCP flow extraction across one or more PCAP files, aggregates
    statistics, computes wildcard byte masks, filters baseline/background noise,
    generates Wireshark/Suricata rules, and exports reports/mindmaps/charts."""

    def __init__(
        self,
        pcap_list,
        tshark_bin="tshark",
        resolve_ip_info=True,
        ip_lookup_timeout=3,
        max_payload_samples=3,
        payload_preview_bytes=32,
    ):
        if isinstance(pcap_list, str):
            self.pcaps = [pcap_list]
        else:
            self.pcaps = list(pcap_list)

        self.tshark_bin = tshark_bin
        self.resolve_ip_info = resolve_ip_info
        self.ip_lookup_timeout = ip_lookup_timeout
        self.max_payload_samples = max_payload_samples
        self.payload_preview_bytes = payload_preview_bytes

        # Maps pcap_path -> dict of flow_id -> TCPFlowObject
        self.pcap_flows = {}
        # Maps pcap_path -> TCPStreamCatcher
        self.catchers = {}

    def extract_pcap_info(self):
        """For each PCAP in the list, instantiates a TCPStreamCatcher worker and extracts flows."""
        for pcap_path in self.pcaps:
            catcher = TCPStreamCatcher(
                pcap_path=pcap_path,
                tshark_bin=self.tshark_bin,
                resolve_ip_info=self.resolve_ip_info,
                ip_lookup_timeout=self.ip_lookup_timeout,
                max_payload_samples=self.max_payload_samples,
                payload_preview_bytes=self.payload_preview_bytes,
            )
            flows = catcher.catch_streams()
            self.catchers[pcap_path] = catcher
            self.pcap_flows[pcap_path] = flows
        return self.pcap_flows

    def get_all_flows(self):
        """Returns a flat list of (pcap_name, flow_obj) across all analyzed PCAPs."""
        all_items = []
        for pcap_path, flows in self.pcap_flows.items():
            pcap_name = os.path.basename(pcap_path)
            for flow_id in sorted(flows.keys(), key=lambda x: int(x) if str(x).isdigit() else str(x)):
                all_items.append((pcap_name, flows[flow_id]))
        return all_items

    def build_baseline_profile(self, baseline_pcaps):
        """Extracts destination IPs, domains, SNIs, and (port, magic) tuples from baseline PCAPs."""
        if isinstance(baseline_pcaps, str):
            baseline_pcaps = [baseline_pcaps]

        profile = {
            "dst_ips": set(),
            "domains": set(),
            "port_magic": set(),
            "ja3_sni": set(),
        }

        for b_pcap in baseline_pcaps:
            catcher = TCPStreamCatcher(
                pcap_path=b_pcap,
                tshark_bin=self.tshark_bin,
                resolve_ip_info=False,
                max_payload_samples=1,
                payload_preview_bytes=16,
            )
            b_flows = catcher.catch_streams()
            for flow in b_flows.values():
                if flow.dst_ip:
                    profile["dst_ips"].add(flow.dst_ip)
                for dom in (flow.primary_domain, flow.dst_fqdn, *(flow.sni_list or []), *(flow.http_hosts or [])):
                    if dom:
                        profile["domains"].add(dom.lower())
                if flow.payload_samples and flow.dst_port:
                    magic = flow.payload_samples[0].get("magic_4bytes")
                    if magic:
                        profile["port_magic"].add((flow.dst_port, magic))
                if flow.ja3_list and flow.sni_list:
                    profile["ja3_sni"].add((flow.ja3_list[0], flow.sni_list[0].lower()))

        return profile

    @staticmethod
    def matches_baseline(flow, baseline_profile):
        """Returns True if a flow matches known endpoints/signatures from the baseline PCAP."""
        if not baseline_profile:
            return False
        if flow.dst_ip and flow.dst_ip in baseline_profile["dst_ips"]:
            return True
        for dom in (flow.primary_domain, flow.dst_fqdn, *(flow.sni_list or []), *(flow.http_hosts or [])):
            if dom and dom.lower() in baseline_profile["domains"]:
                return True
        if flow.payload_samples and flow.dst_port:
            magic = flow.payload_samples[0].get("magic_4bytes")
            if magic and (flow.dst_port, magic) in baseline_profile["port_magic"]:
                return True
        if flow.ja3_list and flow.sni_list:
            if (flow.ja3_list[0], flow.sni_list[0].lower()) in baseline_profile["ja3_sni"]:
                return True
        return False

    @staticmethod
    def _extract_contiguous_segments(byte_matrix, min_len=16):
        """Aligns multiple byte sequences of length >= min_len and finds fixed positions vs wildcards."""
        if not byte_matrix:
            return "", "", []

        aligned_len = min(len(b) for b in byte_matrix)
        aligned_len = min(aligned_len, min_len)
        if aligned_len == 0:
            return "", "", []

        hex_tokens = []
        ascii_tokens = []
        fixed_mask = []  # byte int or None for wildcard

        for pos in range(aligned_len):
            vals = {b[pos] for b in byte_matrix}
            if len(vals) == 1:
                val = next(iter(vals))
                hex_tokens.append(f"{val:02x}")
                ascii_tokens.append(chr(val) if 32 <= val <= 126 else ".")
                fixed_mask.append(val)
            else:
                hex_tokens.append("[??]")
                ascii_tokens.append("?")
                fixed_mask.append(None)

        # Extract contiguous runs of fixed bytes for Suricata/Snort content clauses
        segments = []
        idx = 0
        while idx < aligned_len:
            if fixed_mask[idx] is not None:
                start = idx
                run = bytearray()
                while idx < aligned_len and fixed_mask[idx] is not None:
                    run.append(fixed_mask[idx])
                    idx += 1
                segments.append(
                    {
                        "offset": start,
                        "length": len(run),
                        "hex_str": " ".join(f"{b:02x}" for b in run),
                        "colon_hex": ":".join(f"{b:02x}" for b in run),
                        "ascii_str": "".join(chr(b) if 32 <= b <= 126 else "." for b in run),
                    }
                )
            else:
                idx += 1

        return " ".join(hex_tokens), "".join(ascii_tokens), segments

    def compute_wildcard_signatures(self, flows_subset=None, max_align_bytes=16):
        """Clusters unknown payload flows by destination port or 2-byte prefix and computes
        wildcard byte masks (e.g., '46 4c 4f 57 59 5f 56 31 00 [??] 00 [??]')."""
        items = flows_subset if flows_subset is not None else self.get_all_flows()
        unknown_flows = [f for _, f in items if f.is_unknown_traffic and f.payload_samples]

        # Group flows by (direction, dst_port, first_2_bytes) for both C->S and S->C
        clusters = defaultdict(list)
        for flow in unknown_flows:
            for sample_list in (flow.c2s_payload_samples, flow.s2c_payload_samples):
                if not sample_list:
                    continue
                sample = sample_list[0]
                raw_hex = sample.get("raw_hex", "")
                if len(raw_hex) < 4:
                    continue
                prefix_2b = raw_hex[:4]
                direction = sample.get("direction", "C->S")
                key = (direction, flow.dst_port, prefix_2b)
                clusters[key].append((flow, bytes.fromhex(raw_hex)))

        signatures = []
        for (direction, dst_port, prefix_2b), entries in clusters.items():
            byte_matrix = [b for _, b in entries]
            flow_ids = [f.flow_id for f, _ in entries]
            entropies = [f.payload_entropy for f, _ in entries if f.payload_entropy is not None]
            avg_entropy = round(sum(entropies) / len(entropies), 2) if entropies else None

            hex_mask, ascii_mask, segments = self._extract_contiguous_segments(
                byte_matrix, min_len=max_align_bytes
            )
            fixed_bytes_count = sum(s["length"] for s in segments)

            signatures.append(
                {
                    "flow_ids": flow_ids,
                    "flow_count": len(flow_ids),
                    "direction": direction,
                    "dst_port": dst_port,
                    "avg_entropy": avg_entropy,
                    "hex_mask": hex_mask,
                    "ascii_mask": ascii_mask,
                    "fixed_bytes_count": fixed_bytes_count,
                    "segments": segments,
                }
            )

        # Sort multi-flow clusters first, then by fixed byte count
        signatures.sort(key=lambda s: (s["flow_count"], s["fixed_bytes_count"]), reverse=True)
        return signatures

    def generate_rules(self, output_path="flow_rules.rules", flows_subset=None):
        """Generates ready-to-use Wireshark display filters and Suricata/Snort IDS rules
        for unknown protocol signatures as well as identified TLS/HTTP services."""
        items = flows_subset if flows_subset is not None else self.get_all_flows()
        wildcard_sigs = self.compute_wildcard_signatures(items)

        rules_list = []
        sid_counter = 1000001

        # 1. Rules for Unknown Payload Signatures (using wildcard byte masks)
        for sig in wildcard_sigs:
            if not sig["segments"]:
                continue

            port_part = str(sig["dst_port"]) if sig["dst_port"] else "any"
            flow_dir = "to_server,established" if sig["direction"] == "C->S" else "from_server,established"

            # Build Wireshark filter using contiguous segments
            ws_clauses = []
            if sig["dst_port"]:
                ws_clauses.append(f"tcp.port == {sig['dst_port']}")
            for seg in sig["segments"][:2]:
                ws_clauses.append(
                    f"tcp.payload[{seg['offset']}:{seg['length']}] == {seg['colon_hex']}"
                )
            ws_filter = " && ".join(ws_clauses)

            # Build Suricata / Snort content clauses (with offset/depth and distance/within)
            content_clauses = []
            prev_end = 0
            for idx, seg in enumerate(sig["segments"][:3]):
                if idx == 0:
                    content_clauses.append(
                        f'content:"|{seg["hex_str"]}|"; offset:{seg["offset"]}; depth:{seg["length"]};'
                    )
                else:
                    gap = seg["offset"] - prev_end
                    content_clauses.append(
                        f'content:"|{seg["hex_str"]}|"; distance:{gap}; within:{seg["length"]};'
                    )
                prev_end = seg["offset"] + seg["length"]

            first_ascii = sig["segments"][0]["ascii_str"]
            dir_tag = "ClientReq" if sig["direction"] == "C->S" else "ServerResp"
            msg_label = (
                f"TCPFLOWY Custom Protocol {dir_tag} [{first_ascii}]"
                if any(c.isalnum() for c in first_ascii)
                else f"TCPFLOWY Binary Protocol {dir_tag} [0x{sig['segments'][0]['hex_str'][:11]}]"
            )
            rule_hdr = (
                f"alert tcp any any -> any {port_part}"
                if sig["direction"] == "C->S"
                else f"alert tcp any {port_part} -> any any"
            )
            suricata_rule = (
                f'{rule_hdr} ('
                f'msg:"{msg_label}"; flow:{flow_dir}; '
                f'{" ".join(content_clauses)} '
                f'sid:{sid_counter}; rev:1;)'
            )
            sid_counter += 1

            rules_list.append(
                {
                    "type": "UNKNOWN_PROTOCOL_SIGNATURE",
                    "streams": sig["flow_ids"],
                    "direction": sig["direction"],
                    "dst_port": sig["dst_port"],
                    "hex_mask": sig["hex_mask"],
                    "ascii_mask": sig["ascii_mask"],
                    "wireshark_filter": ws_filter,
                    "suricata_rule": suricata_rule,
                }
            )

        # 2. Rules for Identified TLS (SNI / JA3) & HTTP Flows
        seen_domains = set()
        for _, flow in items:
            if flow.is_background_noise:
                continue
            if flow.sni_list:
                sni = flow.sni_list[0]
                if sni in seen_domains:
                    continue
                seen_domains.add(sni)
                ws_f = f'tls.handshake.extensions_server_name == "{sni}"'
                if flow.ja3_list:
                    ws_f += f' && tls.handshake.ja3 == "{flow.ja3_list[0]}"'
                suri = (
                    f'alert tls any any -> any any ('
                    f'msg:"TCPFLOWY TLS Service [{sni}]"; flow:to_server,established; '
                    f'tls.sni; content:"{sni}"; sid:{sid_counter}; rev:1;)'
                )
                sid_counter += 1
                rules_list.append(
                    {
                        "type": "TLS_SERVICE",
                        "streams": [flow.flow_id],
                        "direction": "C->S",
                        "dst_port": flow.dst_port,
                        "hex_mask": None,
                        "ascii_mask": sni,
                        "wireshark_filter": ws_f,
                        "suricata_rule": suri,
                    }
                )
            elif flow.http_hosts:
                host = flow.http_hosts[0]
                if host in seen_domains:
                    continue
                seen_domains.add(host)
                ws_f = f'http.host == "{host}"'
                suri = (
                    f'alert http any any -> any any ('
                    f'msg:"TCPFLOWY HTTP Service [{host}]"; flow:to_server,established; '
                    f'http.host; content:"{host}"; sid:{sid_counter}; rev:1;)'
                )
                sid_counter += 1
                rules_list.append(
                    {
                        "type": "HTTP_SERVICE",
                        "streams": [flow.flow_id],
                        "direction": "C->S",
                        "dst_port": flow.dst_port,
                        "hex_mask": None,
                        "ascii_mask": host,
                        "wireshark_filter": ws_f,
                        "suricata_rule": suri,
                    }
                )

        if output_path:
            lines = [
                "# ======================================================================",
                "# tcpflowy — Auto-Generated Wireshark Filters & Suricata/Snort IDS Rules",
                "# ======================================================================",
                "",
            ]
            for r in rules_list:
                streams_str = ", ".join(f"#{s}" for s in r["streams"])
                lines.append(f"# [{r['type']}] Streams: {streams_str} | Direction: {r['direction']}")
                if r.get("hex_mask"):
                    lines.append(f"# Byte Mask : {r['hex_mask']}  (ASCII: {r['ascii_mask']})")
                lines.append(f"# Wireshark : {r['wireshark_filter']}")
                lines.append(r["suricata_rule"])
                lines.append("")

            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))

        return rules_list

    def get_statistics(self, flows_subset=None):
        """Computes aggregated traffic statistics and unknown-traffic DPI patterns."""
        items = flows_subset if flows_subset is not None else self.get_all_flows()

        app_flow_counts = Counter()
        app_byte_counts = Counter()
        domain_byte_counts = Counter()
        dst_ip_counts = Counter()
        org_counts = Counter()
        ja3_counts = Counter()

        magic_counter = Counter()
        unknown_port_counter = Counter()
        unknown_ascii_counter = Counter()
        unknown_flows = []
        noise_count = 0

        total_packets = 0
        total_bytes = 0
        total_payload_bytes = 0

        for pcap_name, flow in items:
            app = flow.detected_application
            app_flow_counts[app] += 1
            app_byte_counts[app] += flow.total_bytes

            total_packets += flow.packet_count
            total_bytes += flow.total_bytes
            total_payload_bytes += flow.payload_bytes

            if flow.is_background_noise:
                noise_count += 1

            if flow.dst_ip:
                dst_ip_counts[flow.dst_ip] += 1

            for j in flow.ja3_list:
                ja3_counts[j] += 1

            domain = flow.primary_domain or flow.dst_ip or "unknown"
            domain_byte_counts[domain] += flow.total_bytes

            org = (flow.dst_attributes or {}).get("org") or (flow.dst_attributes or {}).get("asn")
            if org:
                org_counts[org] += 1

            if flow.is_unknown_traffic:
                unknown_flows.append((pcap_name, flow))
                if flow.dst_port:
                    unknown_port_counter[str(flow.dst_port)] += 1
                if flow.payload_samples:
                    sample = flow.payload_samples[0]
                    if sample.get("magic_4bytes"):
                        magic_counter[sample["magic_4bytes"]] += 1
                    ascii_pref = sample.get("ascii_prefix", "")[:8].strip()
                    if ascii_pref:
                        unknown_ascii_counter[ascii_pref] += 1

        wildcard_signatures = self.compute_wildcard_signatures(items)

        return {
            "total_pcaps": len(self.pcaps),
            "total_flows": len(items),
            "background_noise_flows": noise_count,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_payload_bytes": total_payload_bytes,
            "flows_by_application": dict(app_flow_counts.most_common()),
            "bytes_by_application": dict(app_byte_counts.most_common()),
            "bytes_by_domain": dict(domain_byte_counts.most_common(15)),
            "flows_by_dst_ip": dict(dst_ip_counts.most_common(15)),
            "flows_by_organization": dict(org_counts.most_common(15)),
            "ja3_fingerprints": dict(ja3_counts.most_common(10)),
            "unknown_traffic": {
                "count": len(unknown_flows),
                "recurring_magic_4bytes": dict(magic_counter.most_common(10)),
                "recurring_dst_ports": dict(unknown_port_counter.most_common(10)),
                "recurring_ascii_prefixes": dict(unknown_ascii_counter.most_common(10)),
                "wildcard_signatures": wildcard_signatures,
            },
        }

    def generate_mindmap(self, output_path="flow_mindmap.md", flows_subset=None):
        """Generates a Markdown file containing a Mermaid mindmap and a Mermaid flowchart
        mapping Client -> Application/Protocol -> Domain/Organization -> TCP Streams."""
        items = flows_subset if flows_subset is not None else self.get_all_flows()

        hierarchy = defaultdict(lambda: defaultdict(list))
        for pcap_name, flow in items:
            app = flow.detected_application
            org = (flow.dst_attributes or {}).get("org")
            domain = flow.primary_domain
            if domain and org and org != "Local Network":
                dest_label = f"{domain} [{org}]"
            elif domain:
                dest_label = f"{domain} ({flow.dst_ip})"
            elif org:
                dest_label = f"{flow.dst_ip} [{org}]"
            else:
                dest_label = f"{flow.dst_ip}:{flow.dst_port}"
            hierarchy[app][dest_label].append((pcap_name, flow))

        def clean_label(text):
            for ch in ("(", ")", "[", "]", '"', "'"):
                text = str(text).replace(ch, "")
            return text.strip()

        lines = [
            "# tcpflowy - Network Traffic Mindmap & Topology",
            "",
            "## 1. Mindmap by Application & Destination",
            "",
            "```mermaid",
            "mindmap",
            "  root((Network Capture))",
        ]

        for app, dests in sorted(hierarchy.items()):
            lines.append(f"    {clean_label(app)}")
            for dest, flow_list in sorted(dests.items()):
                total_b = sum(f.total_bytes for _, f in flow_list)
                stream_ids = ", ".join(f"#{f.flow_id}" for _, f in flow_list[:6])
                if len(flow_list) > 6:
                    stream_ids += f" +{len(flow_list) - 6} more"
                lines.append(f"      {clean_label(dest)}")
                lines.append(f"        Streams {stream_ids} - {total_b} B")

        lines.extend([
            "```",
            "",
            "## 2. Flow Relationship Graph",
            "",
            "```mermaid",
            "flowchart LR",
        ])

        node_idx = 0
        node_map = {}

        def get_node_id(key, label):
            nonlocal node_idx
            if key not in node_map:
                node_idx += 1
                nid = f"N{node_idx}"
                safe_lbl = str(label).replace('"', "'")
                node_map[key] = (nid, safe_lbl)
            return node_map[key][0]

        for pcap_name, flow in items:
            src_key = f"src:{flow.src_ip}"
            src_id = get_node_id(src_key, flow.src_fqdn or flow.src_ip or "Unknown Src")

            app_key = f"app:{flow.detected_application}"
            app_id = get_node_id(app_key, flow.detected_application)

            dst_label = flow.primary_domain or flow.dst_ip or "Unknown Dst"
            org = (flow.dst_attributes or {}).get("org")
            if org and org != "Local Network":
                dst_label = f"{dst_label}\\n({org})"
            dst_key = f"dst:{flow.dst_ip}:{flow.primary_domain}"
            dst_id = get_node_id(dst_key, dst_label)

            lines.append(f'    {src_id}["{node_map[src_key][1]}"] --> {app_id}(["{node_map[app_key][1]}"])')
            lines.append(
                f'    {app_id} -->|Stream #{flow.flow_id}: {flow.total_bytes}B| {dst_id}["{node_map[dst_key][1]}"]'
            )

        seen_edges = set()
        dedup_lines = []
        for line in lines:
            if "-->" in line:
                if line in seen_edges:
                    continue
                seen_edges.add(line)
            dedup_lines.append(line)

        dedup_lines.append("```")
        dedup_lines.append("")

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(dedup_lines))

        return output_path

    def render_ascii_chart(self, flows_subset=None, width=36):
        """Returns a formatted ASCII bar chart string for terminal display."""
        stats = self.get_statistics(flows_subset)
        bytes_by_app = stats["bytes_by_application"]
        if not bytes_by_app:
            return "No traffic data available to chart."

        max_val = max(bytes_by_app.values()) or 1
        out = [
            "=== Traffic Volume by Application/Protocol (Bytes) ===",
        ]
        for app, count in bytes_by_app.items():
            bar_len = int((count / max_val) * width)
            bar = "█" * max(1, bar_len) if count > 0 else ""
            flow_cnt = stats["flows_by_application"].get(app, 0)
            out.append(f"  {app:<24} | {bar:<{width}} {count:>10,} B ({flow_cnt} flows)")
        return "\n".join(out)

    def generate_chart(self, output_path="flow_chart.html", flows_subset=None):
        """Generates a self-contained HTML visual report with bar charts, entropy, direction, and flow table."""
        stats = self.get_statistics(flows_subset)
        items = flows_subset if flows_subset is not None else self.get_all_flows()

        bytes_by_app = stats["bytes_by_application"]
        max_app_bytes = max(bytes_by_app.values()) if bytes_by_app else 1

        bytes_by_domain = stats["bytes_by_domain"]
        max_dom_bytes = max(bytes_by_domain.values()) if bytes_by_domain else 1

        app_bars_html = []
        for app, val in bytes_by_app.items():
            pct = round((val / max_app_bytes) * 100, 1)
            f_cnt = stats["flows_by_application"].get(app, 0)
            app_bars_html.append(
                f"""
                <div class="bar-row">
                    <div class="bar-label">{html.escape(str(app))}</div>
                    <div class="bar-track">
                        <div class="bar-fill" style="width: {max(pct, 2)}%;"></div>
                    </div>
                    <div class="bar-value">{val:,} B ({f_cnt} flows)</div>
                </div>"""
            )

        dom_bars_html = []
        for dom, val in bytes_by_domain.items():
            pct = round((val / max_dom_bytes) * 100, 1)
            dom_bars_html.append(
                f"""
                <div class="bar-row">
                    <div class="bar-label">{html.escape(str(dom))}</div>
                    <div class="bar-track">
                        <div class="bar-fill bar-fill-alt" style="width: {max(pct, 2)}%;"></div>
                    </div>
                    <div class="bar-value">{val:,} B</div>
                </div>"""
            )

        flow_rows_html = []
        for pcap_name, flow in items:
            domain = flow.primary_domain or "-"
            org = (flow.dst_attributes or {}).get("org") or "-"
            country = (flow.dst_attributes or {}).get("countryCode") or ""
            org_display = f"{org} ({country})" if country else org
            payload_preview = ""
            if flow.payload_samples:
                s0 = flow.payload_samples[0]
                payload_preview = (
                    f"<b>[{html.escape(s0.get('direction', 'C->S'))}]</b> "
                    f"<code>{html.escape(s0['hex_prefix'][:29])}</code><br>"
                    f"<small>{html.escape(s0['ascii_prefix'])}</small>"
                )
            badge_cls = "badge-unknown" if flow.is_unknown_traffic else "badge-known"
            ent_str = (
                f"{flow.payload_entropy:.2f} b/B<br><small>{html.escape(flow.entropy_profile)}</small>"
                if flow.payload_entropy is not None
                else "-"
            )
            dir_str = (
                f"↑ {flow.c2s_bytes:,}B / ↓ {flow.s2c_bytes:,}B<br>"
                f"<small>{html.escape(flow.direction_profile)}</small>"
            )
            flow_rows_html.append(
                f"""
                <tr>
                    <td>#{html.escape(str(flow.flow_id))}</td>
                    <td>{html.escape(str(flow.src_ip))}:{html.escape(str(flow.src_port))}</td>
                    <td>{html.escape(str(flow.dst_ip))}:{html.escape(str(flow.dst_port))}</td>
                    <td><strong>{html.escape(str(domain))}</strong></td>
                    <td>{html.escape(str(org_display))}</td>
                    <td><span class="badge {badge_cls}">{html.escape(str(flow.detected_application))}</span></td>
                    <td>{dir_str}</td>
                    <td>{ent_str}</td>
                    <td>{payload_preview}</td>
                </tr>"""
            )

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>tcpflowy - Network Traffic & Flow Analysis Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
    h1, h2 {{ color: #f8fafc; margin-top: 0; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; margin-bottom: 20px; }}
    .metric-val {{ font-size: 1.75rem; font-weight: 700; color: #38bdf8; }}
    .metric-lbl {{ font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 20px; margin-bottom: 24px; }}
    .bar-row {{ display: flex; align-items: center; margin-bottom: 10px; gap: 12px; font-size: 0.9rem; }}
    .bar-label {{ width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #cbd5e1; }}
    .bar-track {{ flex: 1; background: #0f172a; height: 14px; border-radius: 7px; overflow: hidden; }}
    .bar-fill {{ background: linear-gradient(90deg, #0284c7, #38bdf8); height: 100%; border-radius: 7px; }}
    .bar-fill-alt {{ background: linear-gradient(90deg, #7c3aed, #a78bfa); }}
    .bar-value {{ width: 150px; text-align: right; color: #94a3b8; font-variant-numeric: tabular-nums; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.86rem; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #334155; text-align: left; vertical-align: top; }}
    th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
    tr:hover {{ background: #26334d; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 5px; font-size: 0.78rem; font-weight: 600; }}
    .badge-known {{ background: #064e3b; color: #6ee7b7; }}
    .badge-unknown {{ background: #7f1d1d; color: #fca5a5; }}
    code {{ color: #fbbf24; font-size: 0.8rem; }}
</style>
</head>
<body>
    <h1>tcpflowy — Network Capture Flow & DPI Report</h1>
    <div class="summary-grid">
        <div class="card"><div class="metric-val">{stats["total_flows"]}</div><div class="metric-lbl">TCP Flows</div></div>
        <div class="card"><div class="metric-val">{stats["total_packets"]:,}</div><div class="metric-lbl">Total Packets</div></div>
        <div class="card"><div class="metric-val">{stats["total_bytes"]:,} B</div><div class="metric-lbl">Total Volume</div></div>
        <div class="card"><div class="metric-val">{stats["unknown_traffic"]["count"]}</div><div class="metric-lbl">Unclassified Payload Flows</div></div>
    </div>

    <div class="charts-grid">
        <div class="card">
            <h2>Traffic Volume by Application / Protocol</h2>
            {"".join(app_bars_html) or "<p>No flows recorded.</p>"}
        </div>
        <div class="card">
            <h2>Top Destinations (Domain / Host / IP)</h2>
            {"".join(dom_bars_html) or "<p>No destinations recorded.</p>"}
        </div>
    </div>

    <div class="card">
        <h2>Extracted TCP Streams (Client -> Server Oriented)</h2>
        <table>
            <thead>
                <tr>
                    <th>Stream</th>
                    <th>Client (Source)</th>
                    <th>Server (Destination)</th>
                    <th>Domain / SNI / Host</th>
                    <th>Org / Country</th>
                    <th>Classification</th>
                    <th>Direction Volume</th>
                    <th>Shannon Entropy</th>
                    <th>First Payload Sample (Hex / ASCII)</th>
                </tr>
            </thead>
            <tbody>
                {"".join(flow_rows_html)}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_doc)

        return output_path

    def export_json(self, output_path="flow_report.json", flows_subset=None):
        """Exports all extracted flow objects, passive DNS mappings, and statistics to JSON."""
        items = flows_subset if flows_subset is not None else self.get_all_flows()
        stats = self.get_statistics(items)

        dns_combined = {}
        for catcher in self.catchers.values():
            dns_combined.update(catcher.dns_map)

        payload = {
            "statistics": stats,
            "passive_dns_map": dns_combined,
            "flows": [
                {"pcap": pcap_name, **flow.to_dict()}
                for pcap_name, flow in items
            ],
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return output_path
