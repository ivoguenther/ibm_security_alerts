"""
Node-page Remediation/Fixes PTF extraction.

Parses IBM Security Bulletin *node* pages
(https://www.ibm.com/support/pages/node/NID) to extract the per-release PTF
records from the page's **Remediation/Fixes** table. Each row of that table
represents an affected product release together with one or more PTF numbers
and their download links, e.g::

    7.6 | 5770-SS1 PTF Number(s) | https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11497

The result is a flat table of one record per (release, PTF)::

    node=7288323, ibm_i_release=7.6, sw_lvl=5770-SS1, ptf=SJ11497, download_link=...

It is intentionally dependency-free (stdlib ``html.parser`` only) and reuses the
shared HTTP/SSL handling from :mod:`ibm_security_bulletin.extractor`.
"""

from __future__ import annotations

import html as _htmlmod
import os
import re
import sqlite3
import time
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from .extractor import (
    DEFAULT_USER_AGENT,
    NODE_URL_TEMPLATE,
    http_fetch_text,
)

# Canonical PTF table columns (the 5 requested + a detected product tag).
PTF_TABLE_COLUMNS = [
    "node",
    "product",
    "ibm_i_release",
    "sw_lvl",
    "ptf_number",
    "download_link",
]

# A PTF number like SJ11497, SF10345, SI13945 (1-4 letters then 3-7 digits).
_PTF_TOKEN = re.compile(r"[A-Za-z]{1,4}\d{3,7}")
# SW level token embedded in the PTF column header, e.g. 5770-SS1 / 5770-TC1.
_SW_LVL = re.compile(r"\d{4}-[A-Za-z]+\d?")
# The remediation field div class on IBM node pages.
_REMEDIATION_FIELD = "field--name-field-remediation-fixes"
_DEFAULT_PTF_LINK = "https://www.ibm.com/mysupport/s/fix-information?legacy={ptf}"


def node_url(nid: Any) -> str:
    """Build the node page URL from a node id."""
    return NODE_URL_TEMPLATE.format(node=str(nid).strip())


def fetch_node_html(
    nid: Any,
    timeout: int = 60,
    user_agent: str = DEFAULT_USER_AGENT,
    insecure: bool = False,
) -> str:
    """Fetch and return the raw HTML of a single node page.

    :param nid: Node id (``nid``) or already-absolute node URL.
    :param timeout: Request timeout in seconds.
    :param user_agent: User-Agent header string.
    :param insecure: Disable SSL certificate verification.
    :return: Decoded node page HTML.
    """
    target = str(nid).strip()
    url = target if target.startswith("http") else node_url(target)
    return http_fetch_text(
        url,
        timeout=timeout,
        user_agent=user_agent,
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        insecure=insecure,
    )


class _RemediationExtractor(HTMLParser):
    """Collect every ``border="1"`` table within the Remediation/Fixes field.

    It walks the whole document while tracking the depth of the
    ``field--name-field-remediation-fixes`` div (nesting-balanced) and, inside
    that field, records the data rows of each top-level table. Each cell keeps
    its stripped text *and* the unescaped hrefs of any anchors it contains, so
    a PTF cell holding several PTF numbers (separated by ``<br>``) is preserved.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: List[List[List[Dict[str, Any]]]] = []
        self._rem_depth = 0
        self._table_depth = 0
        self._table: Optional[List[List[Dict[str, Any]]]] = None
        self._row: Optional[List[Dict[str, Any]]] = None
        self._cell: Optional[Dict[str, Any]] = None

    # -- div handling: stay inside the remediation field ----------------------
    def _is_remediation_div(self, attrs: List[Tuple[str, Optional[str]]]) -> bool:
        parts = [v for k, v in attrs if k == "class"]
        joined = " ".join((p or "") for p in parts)
        return _REMEDIATION_FIELD in joined

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "div":
            if self._is_remediation_div(attrs) and self._rem_depth == 0:
                self._rem_depth = 1
            elif self._rem_depth > 0:
                self._rem_depth += 1
            return

        if self._rem_depth == 0:
            return

        if tag == "table":
            self._table_depth += 1
            if self._table_depth == 1:
                self._table = []
                self._row = None
            return

        if self._table_depth == 0:
            return

        # Only top-level tables contribute rows/cells.
        if self._table_depth > 1:
            return

        if tag == "tr" and self._table is not None:
            self._row = []
            if self._table is not None:
                self._table.append(self._row)
            return
        if tag in ("td", "th") and self._row is not None:
            self._cell = {"text": "", "links": [], "tag": tag}
            self._row.append(self._cell)
            return
        if tag == "a":
            href = None
            for k, v in attrs:
                if k == "href":
                    href = v
                    break
            if href and self._cell is not None:
                self._cell["links"].append(_htmlmod.unescape(href))
            return
        if tag == "br" and self._cell is not None:
            self._cell["text"] += "\n"
            return

    def handle_data(self, data: str) -> None:
        if self._rem_depth == 0 or self._table_depth != 1 or self._cell is None:
            return
        text = data.replace("\xa0", " ")
        self._cell["text"] += text

    def handle_endtag(self, tag: str) -> None:
        if tag == "div":
            if self._rem_depth > 0:
                self._rem_depth -= 1
                if self._rem_depth == 0:
                    self._finalize_table()
            return

        if self._rem_depth == 0:
            return

        if tag == "table":
            if self._table_depth >= 1:
                self._table_depth -= 1
                if self._table_depth == 0:
                    self._finalize_table()
            return

        if tag == "tr" and self._row is not None and self._table_depth == 1:
            self._row = None
            return

        if tag in ("td", "th") and self._cell is not None and self._table_depth == 1:
            self._cell = None
            return

    def _finalize_table(self) -> None:
        if self._table:
            self.tables.append(self._table)
        self._table = None
        self._row = None
        self._cell = None
        self._table_depth = 0


# -- small cell / column helpers --------------------------------------------

def _cell_text(cell: Dict[str, Any]) -> str:
    """Whitespace-normalised (but newline-preserving) text of a parsed cell."""
    return re.sub(r"[ \t]+", " ", cell.get("text", ""))


def _split_ptfs(text: str) -> List[str]:
    """Extract PTF numbers from a cell, upper-cased, preserving order."""
    seen: set = set()
    out: List[str] = []
    for m in _PTF_TOKEN.findall(text):
        up = m.upper()
        if up not in seen:
            seen.add(up)
            out.append(up)
    return out


def _normalize_release(raw: str) -> str:
    """Collapse a release cell to a clean value (e.g. '7.6')."""
    raw = raw.replace("\n", " ")
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw


def _collect_links(row: List[Dict[str, Any]], column_indices: List[int]) -> List[str]:
    """Gather ``fix-information`` hrefs from the given row columns, in order."""
    links: List[str] = []
    for idx in column_indices:
        if 0 <= idx < len(row):
            for href in row[idx].get("links", []):
                h = href.strip()
                if h and re.search(r"fix-information", h, re.I):
                    if h not in links:
                        links.append(h)
    return links


def _extract_sw_lvl(header_texts: Optional[List[str]]) -> str:
    """Extract the SW level token (e.g. '5770-SS1') from the PTF column header."""
    if not header_texts:
        return ""
    m = _SW_LVL.search(" ".join(header_texts))
    return m.group(0) if m else ""


def _find_header_row(rows: List[List[Dict[str, Any]]]) -> Optional[int]:
    """Return the index of the table header row, or None.

    A header row is the first row that reads like a column label set (contains
    words such as 'release', 'version', 'ptf', 'number', 'download') *and* does
    not itself look like a data row (whose first cell is a bare version like
    '7.6').
    """
    for i, r in enumerate(rows):
        text = " ".join(_cell_text(c) for c in r).lower()
        if re.search(r"release|version|ptf|download|number|link", text):
            first = _cell_text(r[0]).lower().strip() if r else ""
            if re.fullmatch(r"\d+\.\d+", first):
                continue
            return i
    return None


def _classify_columns(
    header_texts: Optional[List[str]], data_rows: List[List[Dict[str, Any]]]
) -> Tuple[int, int, int]:
    """Infer (release_col, ptf_col, link_col) for a remediation table.

    Prefers header keywords, then falls back to positional heuristics and
    content-based hints in the data rows. Always returns in-range column
    indices for the common 3-column IBM i layout.
    """
    n = 3
    for r in data_rows:
        if len(r) > n:
            n = len(r)

    release_col, ptf_col, link_col = 0, 1, 2
    if header_texts:
        for idx, h in enumerate(header_texts):
            hl = (h or "").lower()
            if re.search(r"release|version|level", hl) and release_col == 0:
                release_col = idx
            if re.search(r"ptf|number", hl):
                ptf_col = idx
            if re.search(r"download|link|url|fix-information", hl):
                link_col = idx

    def col_has(idx: int, pred) -> bool:
        return any(0 <= idx < len(r) and pred(_cell_text(r[idx])) for r in data_rows)

    has_url = lambda t: "http" in t.lower() or "fix-information" in t.lower()
    has_ptf = lambda t: bool(_split_ptfs(t))
    has_release = lambda t: bool(re.search(r"\d+\.\d+", t))

    headerless = header_texts is None or len(header_texts) < 3
    if headerless:
        link_idx = next((i for i in range(0, n) if col_has(i, has_url)), link_col)
        ptf_idx = next((i for i in range(0, n) if col_has(i, has_ptf)), ptf_col)
        rel_idx = next((i for i in range(0, n) if col_has(i, has_release)), release_col)
        if link_idx == ptf_idx:
            link_idx = n - 1
        if ptf_idx == rel_idx:
            ptf_idx = rel_idx + 1 if rel_idx + 1 < n else ptf_idx
        release_col, ptf_col, link_col = rel_idx, ptf_idx, link_idx

    release_col = 0 if release_col is None or release_col >= n else release_col
    ptf_col = (release_col + 1) if ptf_col is None or ptf_col >= n else ptf_col
    link_col = (n - 1) if link_col is None or link_col >= n else link_col
    if ptf_col == link_col:
        ptf_col = link_col - 1 if link_col - 1 >= 0 else link_col
    return release_col, ptf_col, link_col


def _extract_product(header_texts: Optional[List[str]], release_col: int) -> str:
    """Best-effort product label from the release column header (e.g. 'IBM i')."""
    if not header_texts or release_col >= len(header_texts):
        return ""
    h = re.sub(r"\brelease\b|\bversion(?:s)?\b", " ", header_texts[release_col], flags=re.I)
    h = re.sub(r"\s+", " ", h).strip()
    return h


def _record(
    node: str,
    release: str,
    sw_lvl: str,
    product: str,
    ptf: str,
    link: str,
) -> Dict[str, Any]:
    return {
        "node": node,
        "product": product,
        "ibm_i_release": release,
        "sw_lvl": sw_lvl,
        "ptf_number": ptf,
        "download_link": link,
    }


def parse_remediation_ptfs(
    html: str,
    node_id: Any,
    include_empty: bool = False,
    synthesize_links: bool = True,
) -> List[Dict[str, Any]]:
    """Parse all Remediation/Fixes PTF rows for a node page into flat records.

    :param html: Raw node page HTML.
    :param node_id: Node id (``nid``); copied into each record's ``node`` field.
    :param include_empty: When True, also emit rows that have a release but no
        concrete PTF number (e.g. 'refer to ...' style text) with an empty
        ``ptf_number``.
    :param synthesize_links: When a PTF has no explicit fix-information link,
        build ``.../fix-information?legacy=<PTF>`` from the PTF number.
    :return: De-duplicated list of PTF records with the canonical PTF columns
        plus a detected ``product`` tag.
    """
    node = str(node_id).strip()
    extractor = _RemediationExtractor()
    extractor.feed(html)
    extractor.close()

    records: List[Dict[str, Any]] = []
    seen: set = set()

    for table_rows in extractor.tables:
        if not table_rows:
            continue

        header_idx = _find_header_row(table_rows)
        header_row = table_rows[header_idx] if header_idx is not None else None
        header_texts = [_cell_text(c) for c in header_row] if header_row else None
        data_rows = [
            r for i, r in enumerate(table_rows)
            if i != header_idx and any(_cell_text(c) for c in r)
        ]

        release_col, ptf_col, link_col = _classify_columns(header_texts, data_rows)
        sw_lvl = _extract_sw_lvl(header_texts)
        product = _extract_product(header_texts, release_col)

        for r in data_rows:
            release = _normalize_release(_cell_text(r[release_col])) if release_col < len(r) else ""
            ptf_raw = _cell_text(r[ptf_col]) if ptf_col < len(r) else ""
            links = _collect_links(r, [link_col, ptf_col])
            ptfs = _split_ptfs(ptf_raw)

            has_content = bool(release or ptfs or links)
            if not has_content:
                continue

            if not ptfs:
                if not include_empty:
                    continue
                link = links[0] if links else ""
                key = (node, release, sw_lvl, "", link)
                if key not in seen:
                    seen.add(key)
                    records.append(_record(node, release, sw_lvl, product, "", link))
                continue

            n_links = len(links)
            for i, ptf in enumerate(ptfs):
                if i < n_links:
                    link = links[i]
                elif n_links:
                    link = links[-1]
                elif synthesize_links:
                    link = _DEFAULT_PTF_LINK.format(ptf=ptf)
                else:
                    link = ""
                key = (node, release, sw_lvl, ptf, link)
                if key in seen:
                    continue
                seen.add(key)
                records.append(_record(node, release, sw_lvl, product, ptf, link))

    return records


def collect_ptfs_for_entries(
    entries: List[Dict[str, Any]],
    timeout: int = 60,
    user_agent: str = DEFAULT_USER_AGENT,
    insecure: bool = False,
    delay: float = 0.2,
    include_empty: bool = False,
    synthesize_links: bool = True,
    log=None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Fetch node pages for the given bulletin entries and parse PTFs.

    Each unique ``nid`` is fetched once (de-duplicated), parsed, and its PTF
    records collected. Network failures are reported but do not stop the run.

    :param entries: Bulletin entries (from :func:`extract_table_entries`).
    :param log: Optional callable receiving one progress line per node.
    :return: ``(ptf_records, stats)`` where ``stats`` counts nodes fetched,
        nodes failed, and records produced.
    """
    all_records: List[Dict[str, Any]] = []
    seen_nodes: set = set()
    stats = {"nodes_fetched": 0, "nodes_failed": 0, "records": 0}

    for e in entries:
        nid = str(e.get("nid") or "").strip()
        if not nid or nid in seen_nodes:
            continue
        seen_nodes.add(nid)

        try:
            page = fetch_node_html(
                nid, timeout=timeout, user_agent=user_agent, insecure=insecure
            )
            if log:
                log(f"node {nid} fetched ({len(page)} bytes)")
            recs = parse_remediation_ptfs(
                page,
                nid,
                include_empty=include_empty,
                synthesize_links=synthesize_links,
            )
            all_records.extend(recs)
            stats["nodes_fetched"] += 1
            stats["records"] += len(recs)
        except Exception as ex:  # noqa: BLE001 - report and continue
            stats["nodes_failed"] += 1
            if log:
                log(f"node {nid} FAILED: {ex}")

        if delay:
            time.sleep(delay)

    return all_records, stats


# -- persistence & joining --------------------------------------------------

def _sanitize_table(name: str, fallback: str) -> str:
    safe = "".join(c for c in (name or "") if c.isalnum() or c == "_")
    return safe or fallback


def export_ptfs_to_sqlite(
    ptfs: List[Dict[str, Any]],
    db_path: str,
    table_name: str = "remediation_ptfs",
) -> int:
    """Export PTF records to a SQLite table.

    Creates (if absent) a ``remediation_ptfs`` table with the canonical columns
    and upserts the given records. Safe to combine with
    :func:`extractor.export_to_sqlite` in the *same* database so the two tables
    can be joined on ``node`` / ``nid``.

    :return: Number of records written.
    """
    dir_name = os.path.dirname(db_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    safe_table = _sanitize_table(table_name, "remediation_ptfs")
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {safe_table} (
                node TEXT,
                product TEXT,
                ibm_i_release TEXT,
                sw_lvl TEXT,
                ptf_number TEXT,
                download_link TEXT,
                PRIMARY KEY (node, ibm_i_release, sw_lvl, ptf_number, download_link)
            )
            """
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_node ON {safe_table}(node)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_ptf ON {safe_table}(ptf_number)"
        )

        rows = [
            (
                str(r.get("node") or ""),
                str(r.get("product") or ""),
                str(r.get("ibm_i_release") or ""),
                str(r.get("sw_lvl") or ""),
                str(r.get("ptf_number") or ""),
                str(r.get("download_link") or ""),
            )
            for r in ptfs
        ]
        cursor.executemany(
            f"""
            INSERT OR REPLACE INTO {safe_table}
                (node, product, ibm_i_release, sw_lvl, ptf_number, download_link)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


FLAT_JOIN_COLUMNS = [
    "node",
    "field_cve_id",
    "field_product",
    "field_cvss_base_score",
    "field_pub_date",
    "bulletin_url",
    "product",
    "ibm_i_release",
    "sw_lvl",
    "ptf_number",
    "download_link",
]


def build_flat_join(
    bullets: List[Dict[str, Any]], ptfs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Cross-join bulletin context with PTF records by node id.

    For each PTF row, emit one flat row per bulletin entry sharing that `node`
    (`nid`). PTF rows whose node has no bulletin context still appear, with empty
    context fields.

    :param bullets: Bulletin entries (from :func:`extract_table_entries`), each
        carrying an ``nid``.
    :param ptfs: PTF records (from :func:`parse_remediation_ptfs`).
    :return: Flat, joined rows ready for CSV/JSON output.
    """
    by_node: Dict[str, List[Dict[str, Any]]] = {}
    for b in bullets:
        nid = str(b.get("nid") or "").strip()
        if nid:
            by_node.setdefault(nid, []).append(b)

    rows: List[Dict[str, Any]] = []
    for p in ptfs:
        node = str(p.get("node") or "")
        matched = by_node.get(node)
        if not matched:
            rows.append({
                "node": node,
                "field_cve_id": "",
                "field_product": "",
                "field_cvss_base_score": "",
                "field_pub_date": "",
                "bulletin_url": "",
                "product": p.get("product", ""),
                "ibm_i_release": p.get("ibm_i_release", ""),
                "sw_lvl": p.get("sw_lvl", ""),
                "ptf_number": p.get("ptf_number", ""),
                "download_link": p.get("download_link", ""),
            })
            continue
        for b in matched:
            rows.append({
                "node": node,
                "field_cve_id": str(b.get("field_cve_id") or ""),
                "field_product": str(b.get("field_product") or ""),
                "field_cvss_base_score": str(b.get("field_cvss_base_score") or ""),
                "field_pub_date": str(b.get("field_pub_date") or ""),
                "bulletin_url": str(b.get("bulletin_url") or ""),
                "product": p.get("product", ""),
                "ibm_i_release": p.get("ibm_i_release", ""),
                "sw_lvl": p.get("sw_lvl", ""),
                "ptf_number": p.get("ptf_number", ""),
                "download_link": p.get("download_link", ""),
            })
    return rows


def format_flat_csv(rows: List[Dict[str, Any]]) -> str:
    """Render flat joined rows as CSV using :data:`FLAT_JOIN_COLUMNS`."""
    import csv
    import io

    if not rows:
        return ""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=FLAT_JOIN_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return out.getvalue()
