#!/usr/bin/env python3
import argparse
from configparser import ConfigParser
import logging
import os
import sys

### ==> CUSTOM MODULES <== ###
from include.ConsoleStyle import ConsoleStyle as C
from include.TCPDataHoarder import TCPDataHoarder
from include.TCPFlowObject import TCPFlowObject


def load_cfg(cfg_path="config.ini"):
    """Loads parameters from config.ini (or a custom path provided via --custom-cfg)."""
    config_object = ConfigParser()
    defaults = {
        "verbose": False,
        "extraction_tool": "tshark",
        "resolve_ip_info": True,
        "ip_lookup_timeout": 3,
        "max_payload_samples": 3,
        "payload_preview_bytes": 32,
        "mindmap_file": "flow_mindmap.md",
        "chart_file": "flow_chart.html",
        "json_file": "flow_report.json",
        "rules_file": "flow_rules.rules",
    }

    if os.path.isfile(cfg_path):
        config_object.read(cfg_path)
        if "GLOBAL" in config_object:
            g = config_object["GLOBAL"]
            defaults["verbose"] = g.getboolean("verbose", fallback=defaults["verbose"])
            defaults["extraction_tool"] = g.get("extraction_tool", fallback=defaults["extraction_tool"])
            defaults["resolve_ip_info"] = g.getboolean("resolve_ip_info", fallback=defaults["resolve_ip_info"])
            defaults["ip_lookup_timeout"] = g.getint("ip_lookup_timeout", fallback=defaults["ip_lookup_timeout"])
            defaults["max_payload_samples"] = g.getint("max_payload_samples", fallback=defaults["max_payload_samples"])
            defaults["payload_preview_bytes"] = g.getint(
                "payload_preview_bytes", fallback=defaults["payload_preview_bytes"]
            )
        if "OUTPUT" in config_object:
            o = config_object["OUTPUT"]
            defaults["mindmap_file"] = o.get("mindmap_file", fallback=defaults["mindmap_file"])
            defaults["chart_file"] = o.get("chart_file", fallback=defaults["chart_file"])
            defaults["json_file"] = o.get("json_file", fallback=defaults["json_file"])
            defaults["rules_file"] = o.get("rules_file", fallback=defaults["rules_file"])

    return defaults


def format_wildcard_mask(hex_mask):
    """Highlights fixed hex bytes in green and wildcard [??] tokens in dim gray."""
    if not hex_mask:
        return ""
    tokens = hex_mask.split(" ")
    styled = [
        C.gray(tok) if tok == "[??]" else C.green(tok, bold=True)
        for tok in tokens
    ]
    return " ".join(styled)


def print_flows_table(flows_with_pcap, verbose=False):
    """Prints a colorized summary table of extracted TCP flows and DPI/TLS details."""
    if not flows_with_pcap:
        print(C.yellow("\n[!] No matching TCP flows found in capture(s)."))
        return

    raw_header = (
        f"{'STREAM':<7} | {'CLIENT (C)':<21} | {'SERVER (S)':<21} | "
        f"{'CLASSIFICATION':<20} | {'PKTS':>5} | {'C->S / S->C BYTES':<19} | "
        f"{'ENTROPY':<10} | {'DOMAIN / SNI / ORG'}"
    )
    sep = C.gray("-" * len(raw_header))
    print("\n" + sep)
    print(C.bold(raw_header))
    print(sep)

    for pcap_name, flow in flows_with_pcap:
        src = f"{flow.src_ip}:{flow.src_port}" if flow.src_ip else "-"
        dst = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_ip else "-"
        app_colored = C.color_app(
            flow.detected_application,
            is_unknown=flow.is_unknown_traffic,
            is_noise=flow.is_background_noise,
        )

        dir_bytes = f"↑{flow.c2s_bytes:>7,} ↓{flow.s2c_bytes:>7,}"
        if flow.payload_entropy is not None:
            ent_raw = f"{flow.payload_entropy:>4.2f} b/B  "
            if flow.payload_entropy < 5.0:
                ent_col = C.green(ent_raw)
            elif flow.payload_entropy <= 6.8:
                ent_col = C.yellow(ent_raw)
            else:
                ent_col = C.magenta(ent_raw, bold=True)
        else:
            ent_col = C.gray(f"{'N/A':<10}")

        domain = flow.primary_domain or "-"
        org = (flow.dst_attributes or {}).get("org")
        country = (flow.dst_attributes or {}).get("countryCode")
        meta_parts = [C.cyan(domain) if domain != "-" else C.gray("-")]
        if org and org != "Local Network":
            meta_parts.append(C.gray(f"[{org}{f'/{country}' if country else ''}]"))
        if flow.is_background_noise:
            meta_parts.append(C.gray("[NOISE]"))
        meta_str = " ".join(meta_parts)

        stream_lbl = C.bold(f"#{flow.flow_id:<6}")
        print(
            f"{stream_lbl} | {src:<21} | {dst:<21} | "
            f"{app_colored} | {flow.packet_count:>5} | {dir_bytes:<19} | "
            f"{ent_col} | {meta_str}"
        )

        if verbose or flow.is_unknown_traffic:
            # Direction & Entropy insight line
            if flow.payload_bytes > 0:
                ent_badge = C.color_entropy(flow.payload_entropy, flow.entropy_profile)
                print(
                    f"         {C.gray('├─')} {C.bold('Flow Profile')} : "
                    f"Direction={C.cyan(flow.direction_profile)} | Entropy={ent_badge}"
                )

            # Extended TLS details (Version, ALPN, JA3, Cert Subject)
            if flow.sni_list or flow.ja3_list or flow.alpn_list or flow.tls_version:
                tls_parts = []
                if flow.tls_version:
                    tls_parts.append(f"Ver={C.cyan(flow.tls_version)}")
                if flow.alpn_list:
                    tls_parts.append(f"ALPN={C.green(','.join(flow.alpn_list))}")
                if flow.ja3_list:
                    tls_parts.append(f"JA3={C.yellow(flow.ja3_list[0])}")
                if flow.cert_subjects:
                    tls_parts.append(f"Cert={C.magenta(','.join(flow.cert_subjects[:2]))}")
                if tls_parts:
                    print(f"         {C.gray('├─')} {C.bold('TLS Metadata')} : {' | '.join(tls_parts)}")

            # HTTP details
            if flow.http_uris:
                print(f"         {C.gray('├─')} {C.bold('HTTP URIs')}    : {C.green(', '.join(flow.http_uris[:3]))}")
            if flow.http_user_agents:
                print(f"         {C.gray('├─')} {C.bold('User-Agent')}   : {C.gray(flow.http_user_agents[0])}")

            # Directional Payload Samples (C->S and S->C)
            for idx, sample in enumerate(flow.payload_samples, start=1):
                is_last = idx == len(flow.payload_samples)
                branch = C.gray("└─" if is_last else "├─")
                dir_tag = sample.get("direction", "C->S")
                dir_colored = C.blue(dir_tag, bold=True) if dir_tag == "C->S" else C.magenta(dir_tag, bold=True)
                print(
                    f"         {branch} Payload #{idx} [{dir_colored}] ({sample['length']:>4}B): "
                    f"HEX[{C.yellow(sample['hex_prefix'])}]  ASCII[{C.green(sample['ascii_prefix'])}]"
                )

    print(sep)


def print_summary_and_patterns(hoarder, flows_subset, suppressed_noise=0, suppressed_baseline=0):
    """Prints aggregate statistics, wildcard byte masks, and DPI pattern insights."""
    stats = hoarder.get_statistics(flows_subset)
    summary_line = (
        f"\n{C.green('[+]', bold=True)} {C.bold('Summary:')} "
        f"{C.cyan(stats['total_flows'], bold=True)} TCP flows | "
        f"{stats['total_packets']:,} packets | "
        f"{stats['total_bytes']:,} total bytes ({stats['total_payload_bytes']:,} payload bytes)"
    )
    print(summary_line)

    if suppressed_noise > 0 or suppressed_baseline > 0:
        print(
            f"    {C.gray('• Filtered Out:')} "
            f"{suppressed_noise} OS/Browser background noise flows, "
            f"{suppressed_baseline} baseline PCAP flows"
        )

    if stats.get("ja3_fingerprints"):
        ja3_str = ", ".join(f"{C.yellow(k)} ({v}x)" for k, v in list(stats["ja3_fingerprints"].items())[:4])
        print(f"    • Top TLS JA3 Client Fingerprints : {ja3_str}")

    unknown = stats["unknown_traffic"]
    if unknown["count"] > 0:
        unk_cnt = unknown["count"]
        print(
            f"\n{C.red('[!]', bold=True)} "
            f"{C.bold(f'Unclassified / Unknown Payload Flows Detected: {unk_cnt}')}"
        )
        if unknown["recurring_magic_4bytes"]:
            magic_str = ", ".join(
                f"{C.yellow('0x' + k, bold=True)} ({v}x)"
                for k, v in unknown["recurring_magic_4bytes"].items()
            )
            print(f"    • Recurring 4-Byte Magic Prefixes : {magic_str}")
        if unknown["recurring_ascii_prefixes"]:
            ascii_str = ", ".join(
                f"{C.green(repr(k), bold=True)} ({v}x)"
                for k, v in unknown["recurring_ascii_prefixes"].items()
            )
            print(f"    • Recurring ASCII Signatures      : {ascii_str}")
        if unknown["recurring_dst_ports"]:
            port_str = ", ".join(
                f"port {C.cyan(k, bold=True)} ({v}x)"
                for k, v in unknown["recurring_dst_ports"].items()
            )
            print(f"    • Destination Ports               : {port_str}")

        wildcard_sigs = unknown.get("wildcard_signatures", [])
        if wildcard_sigs:
            print(f"\n{C.cyan('[*]', bold=True)} {C.bold('Inferred Wildcard Byte-Mask Signatures (Offset 0 Alignment):')}")
            for sig in wildcard_sigs:
                streams_lbl = ", ".join(f"#{s}" for s in sig["flow_ids"])
                port_lbl = f":{sig['dst_port']}" if sig["dst_port"] else ":any"
                ent_lbl = f"{sig['avg_entropy']:.2f} b/B" if sig["avg_entropy"] is not None else "N/A"
                print(
                    f"    ├─ Cluster [{C.bold(streams_lbl)}] ({sig['direction']} {port_lbl} | Avg Entropy: {ent_lbl})"
                )
                print(f"    │    Mask HEX   : {format_wildcard_mask(sig['hex_mask'])}")
                print(f"    └─   Mask ASCII : {C.cyan(sig['ascii_mask'], bold=True)}")


def print_generated_rules(rules_list, rules_path):
    """Prints the generated Wireshark display filters and Suricata/Snort rules."""
    if not rules_list:
        return
    print(f"\n{C.magenta('[#]', bold=True)} {C.bold('Auto-Generated Wireshark Filters & Suricata/Snort Rules:')}")
    for r in rules_list:
        streams_str = ", ".join(f"#{s}" for s in r["streams"])
        badge = C.red(r["type"], bold=True) if "UNKNOWN" in r["type"] else C.cyan(r["type"], bold=True)
        print(f"  • [{badge}] (Streams: {streams_str})")
        print(f"      {C.bold('Wireshark :')} {C.yellow(r['wireshark_filter'])}")
        print(f"      {C.bold('Suricata  :')} {C.green(r['suricata_rule'])}")
    print(f"\n{C.green('[+]', bold=True)} Saved {len(rules_list)} IDS rules & Wireshark filters to: {C.bold(rules_path)}")


def main():
    parser = argparse.ArgumentParser(
        description="tcpflowy - Inspect TCP streams, identify services/IPs, filter noise, and discover DPI/IDS signatures."
    )
    parser.add_argument(
        "pcap",
        nargs="+",
        type=str,
        help="One or more .pcap / .pcapng files to be scanned",
    )
    parser.add_argument(
        "-t",
        "--extraction-tool",
        help="Specify which tool should be used to process the given PCAP (default: 'tshark')",
        default=None,
    )
    parser.add_argument(
        "--custom-cfg",
        help="Path to a custom configuration .ini file (default: 'config.ini')",
        default="config.ini",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Increase output verbosity (shows directional payload samples, entropy, and TLS/HTTP metadata)",
        action="store_true",
    )
    parser.add_argument(
        "-M",
        "--mindmap",
        help="Generates a Markdown/Mermaid mindmap & topology file with the extracted data",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--generate-chart",
        help="Generates an ASCII chart in terminal and an interactive HTML report",
        action="store_true",
    )
    parser.add_argument(
        "-j",
        "--json",
        help="Exports the extracted flow data and statistics to a JSON file",
        action="store_true",
    )
    parser.add_argument(
        "-R",
        "--generate-rules",
        help="Generates ready-to-use Wireshark display filters and Suricata/Snort IDS rules",
        action="store_true",
    )
    parser.add_argument(
        "-n",
        "--filter-noise",
        help="Suppresses known OS/Browser background telemetry, captive portal, and OCSP/CRL flows",
        action="store_true",
    )
    parser.add_argument(
        "-b",
        "--baseline",
        nargs="+",
        help="One or more baseline/idle PCAP files whose endpoints and signatures should be subtracted",
        default=None,
    )
    parser.add_argument(
        "--filter-ip",
        help="Only show TCP flows involving the specified IP address (as source or destination)",
        default=None,
    )
    parser.add_argument(
        "--stream",
        help="Inspect a specific TCP stream ID in detail",
        default=None,
    )
    parser.add_argument(
        "--unknown-only",
        help="Only display flows with unclassified L7 payload traffic (for IDS/DPI signature analysis)",
        action="store_true",
    )
    parser.add_argument(
        "--no-ip-lookup",
        help="Disable external WHOIS/GeoIP/ASN lookups (offline mode, uses only passive DNS from PCAP)",
        action="store_true",
    )
    parser.add_argument(
        "--no-color",
        help="Disable ANSI color output in terminal",
        action="store_true",
    )
    parser.add_argument(
        "--color",
        help="Force ANSI color output even when piped",
        action="store_true",
    )

    script_args = parser.parse_args()
    cfg = load_cfg(script_args.custom_cfg)

    if script_args.no_color:
        C.set_enabled(False)
    elif script_args.color or os.environ.get("NO_COLOR") is None:
        C.set_enabled(True)

    verbose = script_args.verbose or cfg["verbose"]
    tshark_bin = script_args.extraction_tool or cfg["extraction_tool"]
    resolve_ip = False if script_args.no_ip_lookup else cfg["resolve_ip_info"]

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    TCPFlowObject.clear_registry()
    hoarder = TCPDataHoarder(
        pcap_list=script_args.pcap,
        tshark_bin=tshark_bin,
        resolve_ip_info=resolve_ip,
        ip_lookup_timeout=cfg["ip_lookup_timeout"],
        max_payload_samples=cfg["max_payload_samples"],
        payload_preview_bytes=cfg["payload_preview_bytes"],
    )

    try:
        baseline_profile = None
        if script_args.baseline:
            baseline_profile = hoarder.build_baseline_profile(script_args.baseline)
            TCPFlowObject.clear_registry()

        hoarder.extract_pcap_info()
    except (FileNotFoundError, RuntimeError) as exc:
        print(C.red(f"[ERROR] {exc}", bold=True), file=sys.stderr)
        sys.exit(1)

    flows = hoarder.get_all_flows()
    suppressed_noise = 0
    suppressed_baseline = 0

    if baseline_profile:
        filtered = []
        for p, f in flows:
            if hoarder.matches_baseline(f, baseline_profile):
                suppressed_baseline += 1
            else:
                filtered.append((p, f))
        flows = filtered

    if script_args.filter_noise:
        filtered = []
        for p, f in flows:
            if f.is_background_noise:
                suppressed_noise += 1
            else:
                filtered.append((p, f))
        flows = filtered

    if script_args.stream is not None:
        flows = [(p, f) for p, f in flows if str(f.flow_id) == str(script_args.stream)]
        verbose = True

    if script_args.filter_ip:
        target_ip = script_args.filter_ip.strip()
        src_matches = set(TCPFlowObject.getFlowIDBySourceIP(target_ip))
        dst_matches = set(TCPFlowObject.getFlowIDByDestIP(target_ip))
        matching_ids = src_matches | dst_matches
        flows = [
            (p, f)
            for p, f in flows
            if f.flow_id in matching_ids or f.src_ip == target_ip or f.dst_ip == target_ip
        ]

    if script_args.unknown_only:
        flows = [(p, f) for p, f in flows if f.is_unknown_traffic]

    print_flows_table(flows, verbose=verbose)
    print_summary_and_patterns(hoarder, flows, suppressed_noise, suppressed_baseline)

    if script_args.generate_rules:
        rules_list = hoarder.generate_rules(cfg["rules_file"], flows)
        print_generated_rules(rules_list, cfg["rules_file"])

    if script_args.generate_chart:
        print("\n" + hoarder.render_ascii_chart(flows))
        chart_path = hoarder.generate_chart(cfg["chart_file"], flows)
        print(f"\n{C.green('[+]', bold=True)} Interactive HTML chart & flow report saved to: {C.bold(chart_path)}")

    if script_args.mindmap:
        mindmap_path = hoarder.generate_mindmap(cfg["mindmap_file"], flows)
        print(f"{C.green('[+]', bold=True)} Mermaid Mindmap & Flow Graph saved to: {C.bold(mindmap_path)}")

    if script_args.json:
        json_path = hoarder.export_json(cfg["json_file"], flows)
        print(f"{C.green('[+]', bold=True)} JSON report saved to: {C.bold(json_path)}")


if __name__ == "__main__":
    main()
