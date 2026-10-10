"""
Command-line interface for the IBM Security Bulletin CVE Extractor.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from typing import Any, Dict, List, Optional

from .extractor import (
    DEFAULT_API_URL,
    export_cves_to_sqlite,
    export_to_sqlite,
    extract_all_cve_ids,
    extract_table_entries,
    fetch_raw_bulletin_data,
    filter_entries,
)
from .node_parser import (
    PTF_TABLE_COLUMNS,
    build_flat_join,
    collect_ptfs_for_entries,
    export_ptfs_to_sqlite,
    format_flat_csv,
)


def format_table(entries: List[Dict[str, Any]], max_rows: Optional[int] = None) -> str:
    """
    Renders a human-readable ASCII table representation of the bulletin entries.
    """
    if not entries:
        return "No entries found."

    display_entries = entries[:max_rows] if max_rows else entries

    headers = ["CVE ID", "Severity", "Publish Date", "Product", "Security Bulletin"]

    rows = []
    for e in display_entries:
        cve = str(e.get("field_cve_id") or "")
        sev = str(e.get("field_cvss_base_score") or "")
        date = str(e.get("field_pub_date") or "")
        prod = str(e.get("field_product") or "")
        title = str(e.get("title") or "")
        rows.append([cve, sev, date, prod, title])

    # Compute column widths (with maximum capping for long titles/products)
    col_max = [18, 12, 12, 35, 60]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            widths[i] = min(max(widths[i], len(val)), col_max[i])

    def truncate(text: str, max_len: int) -> str:
        if len(text) > max_len:
            return text[: max_len - 3] + "..."
        return text

    sep_line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    header_line = (
        "|"
        + "|".join(f" {headers[i].ljust(widths[i])} " for i in range(len(headers)))
        + "|"
    )

    out = [sep_line, header_line, sep_line]
    for row in rows:
        rendered_row = (
            "|"
            + "|".join(
                f" {truncate(row[i], widths[i]).ljust(widths[i])} "
                for i in range(len(row))
            )
            + "|"
        )
        out.append(rendered_row)
    out.append(sep_line)

    if max_rows and len(entries) > max_rows:
        out.append(f"... showing {max_rows} of {len(entries)} total entries.")

    return "\n".join(out)


def format_csv(entries: List[Dict[str, Any]]) -> str:
    """
    Formats the entries as CSV.
    """
    if not entries:
        return ""

    fieldnames = [
        "field_cve_id",
        "field_cvss_base_score",
        "field_pub_date",
        "field_product",
        "title",
        "nid",
        "bulletin_url",
        "field_x_force_url",
        "field_oc_code",
        "field_offering_pid_number",
        "field_cvss_desc",
        "field_reported_date",
        "field_section_id",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for entry in entries:
        writer.writerow(entry)
    return output.getvalue()


def format_ptf_csv(ptfs: List[Dict[str, Any]]) -> str:
    """
    Renders PTF records as CSV using the canonical PTF columns.
    """
    if not ptfs:
        return ""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=PTF_TABLE_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for p in ptfs:
        writer.writerow(p)
    return output.getvalue()


def format_ptf_table(ptfs: List[Dict[str, Any]], max_rows: Optional[int] = None) -> str:
    """
    Renders PTF records as a compact ASCII table.
    """
    if not ptfs:
        return "No PTF entries found."

    cols = ["node", "ibm_i_release", "product", "sw_lvl", "ptf_number", "download_link"]
    headers = ["Node", "Release", "Product", "SW_LVL", "PTF", "Download Link"]
    col_max = [12, 12, 14, 12, 12, 55]
    widths = [len(h) for h in headers]

    for p in (ptfs[:max_rows] if max_rows else ptfs):
        for i, key in enumerate(cols):
            widths[i] = min(max(widths[i], len(str(p.get(key) or ""))), col_max[i])

    def truncate(text: str, max_len: int) -> str:
        return text[: max_len - 3] + "..." if len(text) > max_len else text

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    header_cells = " | ".join(f"{h.ljust(widths[i])}" for i, h in enumerate(headers))
    out = [sep, "| " + header_cells + " |", sep]
    for p in (ptfs[:max_rows] if max_rows else ptfs):
        cells = " | ".join(
            f"{truncate(str(p.get(k) or ''), widths[i]).ljust(widths[i])}"
            for i, k in enumerate(cols)
        )
        out.append("| " + cells + " |")
    out.append(sep)

    if max_rows and len(ptfs) > max_rows:
        out.append(f"... showing {max_rows} of {len(ptfs)} total PTF entries.")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract raw CVE entries from IBM Security Bulletins (https://www.ibm.com/support/pages/bulletin/)."
    )

    parser.add_argument(
        "search_query",
        nargs="?",
        default=None,
        help="Search query parameter to query IBM Bulletins (e.g. 'IBM i' or 'AIX').",
    )
    parser.add_argument(
        "-s",
        "--search",
        dest="search_flag",
        type=str,
        default=None,
        help="Search query parameter to query IBM Bulletins (e.g. 'IBM i' or 'AIX').",
    )
    parser.add_argument(
        "-q",
        "--query",
        dest="query_flag",
        type=str,
        default=None,
        help="Alias for search query parameter (e.g. 'IBM i' or 'AIX').",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "raw", "csv", "table", "sqlite"],
        default="json",
        help="Output format: 'json' (parsed table records), 'raw' (unaltered IBM API response), 'csv', 'table', or 'sqlite' (default: %(default)s).",
    )
    parser.add_argument(
        "-d",
        "--sqlite",
        "--db",
        dest="sqlite_path",
        type=str,
        default=None,
        help="File path to export entries to a SQLite database (e.g. 'bulletins.db').",
    )
    parser.add_argument(
        "--table-name",
        type=str,
        default=None,
        help="Custom table name for SQLite database (default: 'bulletins' or 'cve_ids').",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to output file. Defaults to standard output.",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        help="Limit number of output records.",
    )
    parser.add_argument(
        "--all-cves",
        action="store_true",
        help="Extract the complete list of all indexed CVE IDs instead of table entries.",
    )
    parser.add_argument(
        "--cve",
        type=str,
        help="Filter entries by CVE ID substring (e.g. 'CVE-2026').",
    )
    parser.add_argument(
        "--product",
        type=str,
        help="Filter entries by product name substring.",
    )
    parser.add_argument(
        "--severity",
        type=str,
        help="Filter entries by severity (e.g. Critical, High, Medium, Low).",
    )
    parser.add_argument(
        "--filter",
        dest="filter_text",
        type=str,
        default=None,
        help="Optional additional local filter across title, product, and CVE.",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary statistics of the retrieved entries to stderr.",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Do not add convenience 'bulletin_url' to the extracted table records.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="JSON indentation spaces (default: %(default)s, set to 0 for compact JSON).",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=None,
        help="Override the default IBM API endpoint URL.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification.",
    )
    parser.add_argument(
        "--remediation",
        action="store_true",
        dest="remediation",
        help="After extracting entries, fetch each node page and parse the "
        "Remediation/Fixes table into one record per (release, PTF). "
        "Adds a 'remediation_ptfs' SQLite table joinable with 'bulletins' on node=nid.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Seconds to wait between node page fetches (default: %(default)s).",
    )
    parser.add_argument(
        "--include-empty-fixes",
        action="store_true",
        dest="include_empty_fixes",
        help="Also emit remediation rows that have a release but no concrete PTF "
        "number (e.g. 'refer to ...' text), with an empty ptf_number.",
    )
    parser.add_argument(
        "--synthesize-links",
        action="store_true",
        dest="synthesize_links",
        default=True,
        help="Build a fix-information download URL from the PTF number when a row "
        "has an explicit PTF but no link. Default: on.",
    )
    parser.add_argument(
        "--no-synthesize-links",
        action="store_false",
        dest="synthesize_links",
        help="Disable URL synthesis for PTF rows that lack an explicit link.",
    )
    parser.add_argument(
        "--flat-csv",
        dest="flat_csv",
        type=str,
        default=None,
        help="Also write a fully joined CSV (bulletin context + PTF columns) to this "
        "path, in addition to the PTF table output.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    search_term = args.search_flag or args.query_flag or args.search_query
    if search_term:
        search_term = search_term.strip()

    if args.summary and search_term:
        sys.stderr.write(f"Searching IBM Security Bulletins for '{search_term}'...\n")

    try:
        raw_data = fetch_raw_bulletin_data(
            api_url=args.api_url,
            search_query=search_term,
            insecure=args.insecure,
        )
    except Exception as e:
        sys.stderr.write(f"Error fetching bulletin data: {e}\n")
        return 1

    target_db = args.sqlite_path or (args.output if args.format == "sqlite" else None)
    if args.format == "sqlite" and not target_db:
        target_db = "bulletins.db"

    # Raw format directly dumps IBM API response
    if args.format == "raw":
        content = json.dumps(
            raw_data, indent=args.indent if args.indent > 0 else None
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content + "\n")
        else:
            sys.stdout.write(content + "\n")
        return 0

    # If --all-cves requested, output the list of all indexed CVE IDs
    if args.all_cves:
        cve_ids = extract_all_cve_ids(raw_data)
        if args.cve:
            cve_filter = args.cve.strip().lower()
            cve_ids = [c for c in cve_ids if cve_filter in c.lower()]
        if args.limit is not None:
            cve_ids = cve_ids[: args.limit]

        if args.summary:
            sys.stderr.write(f"Total CVE IDs extracted: {len(cve_ids)}\n")

        if target_db:
            tbl = args.table_name or "cve_ids"
            count = export_cves_to_sqlite(cve_ids, db_path=target_db, table_name=tbl)
            sys.stderr.write(
                f"Exported {count} CVE IDs to SQLite database: {target_db} (table: {tbl})\n"
            )
            if args.format == "sqlite":
                return 0

        if args.format == "json":
            content = json.dumps(
                cve_ids, indent=args.indent if args.indent > 0 else None
            )
        elif args.format == "csv":
            content = "cve_id\n" + "\n".join(cve_ids) + "\n"
        else:  # table or plain list
            content = "\n".join(cve_ids)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content if content.endswith("\n") else content + "\n")
        else:
            sys.stdout.write(content if content.endswith("\n") else content + "\n")
        return 0

    # Otherwise extract the datatable records (results.top_records or search results)
    entries = extract_table_entries(raw_data, enrich_urls=not args.no_enrich)

    # Apply filters
    entries = filter_entries(
        entries,
        cve=args.cve,
        product=args.product,
        severity=args.severity,
        query=args.filter_text,
    )

    if args.limit is not None:
        entries = entries[: args.limit]

    # --remediation: fetch each node page and parse the Remediation/Fixes PTF table.
    if args.remediation:
        ptfs, stats = collect_ptfs_for_entries(
            entries,
            insecure=args.insecure,
            delay=args.delay,
            include_empty=args.include_empty_fixes,
            synthesize_links=args.synthesize_links,
            log=(lambda m: sys.stderr.write(m + "\n")) if args.summary else None,
        )

        # Persist both tables into a single DB so they join on node = nid.
        if target_db:
            export_to_sqlite(
                entries, db_path=target_db, table_name=(args.table_name or "bulletins")
            )
            n_ptf = export_ptfs_to_sqlite(
                ptfs, db_path=target_db, table_name="remediation_ptfs"
            )
            sys.stderr.write(
                f"Exported {len(entries)} bulletins + {n_ptf} PTF rows to SQLite: {target_db}\n"
            )
            sys.stderr.write(
                "Join hint: SELECT b.nid, r.ptf_number FROM bulletins b "
                "JOIN remediation_ptfs r ON b.nid = r.node\n"
            )
            if args.format == "sqlite":
                return 0

        # Optional fully-joined CSV (bulletin context + PTF columns).
        if args.flat_csv:
            flat = build_flat_join(entries, ptfs)
            csv_text = format_flat_csv(flat)
            with open(args.flat_csv, "w", encoding="utf-8") as f:
                f.write(csv_text if csv_text.endswith("\n") else csv_text + "\n")
            sys.stderr.write(
                f"Wrote {len(flat)} joined rows to flat CSV: {args.flat_csv}\n"
            )

        # Emit the PTF table to stdout/output in the requested format.
        if args.format == "csv":
            content = format_ptf_csv(ptfs)
        elif args.format == "table":
            content = format_ptf_table(ptfs)
        else:
            content = json.dumps(ptfs, indent=args.indent if args.indent > 0 else None)

        if args.summary:
            sys.stderr.write(
                f"Remediation: {stats['nodes_fetched']} nodes fetched, "
                f"{stats['nodes_failed']} failed, {len(ptfs)} PTF rows\n"
            )

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(content if content.endswith("\n") else content + "\n")
        else:
            sys.stdout.write(content if content.endswith("\n") else content + "\n")

        return 0

    if target_db:
        tbl = args.table_name or "bulletins"
        count = export_to_sqlite(entries, db_path=target_db, table_name=tbl)
        sys.stderr.write(
            f"Exported {count} entries to SQLite database: {target_db} (table: {tbl})\n"
        )
        if args.format == "sqlite":
            return 0

    if args.summary:
        unique_cves = len(
            set(e.get("field_cve_id") for e in entries if e.get("field_cve_id"))
        )
        unique_prods = len(
            set(e.get("field_product") for e in entries if e.get("field_product"))
        )
        sys.stderr.write(
            f"Extracted {len(entries)} records | {unique_cves} unique CVEs | {unique_prods} products\n"
        )

    # Format output
    if args.format == "json":
        indent_val = args.indent if args.indent > 0 else None
        content = json.dumps(entries, indent=indent_val)
    elif args.format == "csv":
        content = format_csv(entries)
    elif args.format == "table":
        content = format_table(entries)
    else:
        content = json.dumps(entries)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content if content.endswith("\n") else content + "\n")
    else:
        sys.stdout.write(content if content.endswith("\n") else content + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
