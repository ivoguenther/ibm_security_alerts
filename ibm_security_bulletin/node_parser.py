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
# A PTF entry: the PTF number plus an optional trailing " - NN" level, e.g.
# "SF99952 - 01" (or ", NN"). Multiple such entries are separated by
# <br>/comma/whitespace. ASCII separators only ('-' and ','), which is what the
# IBM data uses.
_PTF_ENTRY = re.compile(
    r"(?P<ptf>[A-Za-z]{1,4}\d{3,7})"
    r"(?P<lvl>(?:[ \t]*[-,][ \t]*(?:level[ \t]*)?\d{1,4}))?"
)
# An IBM i release/version like 7.6, 7.4.1, V7R2 -> 7.2.
_VERSION = re.compile(r"\d+\.\d+\.\d+|\d+\.\d+|V\d+R\d+")
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
    """Extract bare PTF numbers from a cell, upper-cased, preserving order.

    Used for content sniffing only; see :func:`extract_ptf_entries` for the
    PTF+level extraction used when building records.
    """
    seen: set = set()
    out: List[str] = []
    for m in _PTF_TOKEN.findall(text):
        up = m.upper()
        if up not in seen:
            seen.add(up)
            out.append(up)
    return out


def extract_versions(raw: str) -> List[str]:
    """Split a release cell into a list of clean version numbers.

    Handles multi-release cells like '7.4 7.3 7.2' and 'V7R2' style text,
    returning a de-duplicated, order-preserving list such as
    ``['7.4', '7.3', '7.2']`` or ``['7.2']``. An unparseable (but non-empty)
    cell falls back to its trimmed text so PTF/fix data is never dropped.
    """
    out: List[str] = []
    for m in _VERSION.finditer(raw or ""):
        tok = m.group(0)
        if tok[:1] == "V":
            tok = re.sub(r"[Rr]", ".", tok[1:])  # '7R2' -> '7.2'
        if tok not in out:
            out.append(tok)
    return out


def normalize_release(raw: str) -> List[str]:
    """Return the list of per-version values to emit for a release cell.

    Produces one clean version per OS release; falls back to the trimmed raw
    text when no version token can be parsed.
    """
    versions = extract_versions(raw)
    if versions:
        return [v for v in versions]
    fallback = re.sub(r"\s+", " ", (raw or "").replace("\n", " ")).strip()
    return [fallback] if fallback else [""]


def extract_ptf_entries(raw: str) -> List[str]:
    """Extract PTF entries (number plus optional '- NN' level) from a cell.

    Multiple PTFs separated by <br>/comma/whitespace are returned as separate
    entries, e.g. ``'SF99952 - 01'`` stays as one entry ``'SF99952 - 01'`` and
    ``'PTF_A PTF_B'`` yields ``['PTF_A', 'PTF_B']``. Order-preserving and
    de-duplicated.
    """
    out: List[str] = []
    for m in _PTF_ENTRY.finditer(raw or ""):
        number = m.group("ptf").upper()
        entry = number
        lvl = m.groupdict().get("lvl")
        if lvl:
            digit = re.search(r"\d{1,4}", lvl)
            if digit:
                entry = f"{number} - {digit.group(0)}"
        if entry not in out:
            out.append(entry)
    return out


def extract_ptf_base(ptf_entry: str) -> str:
    """Return the bare PTF number (no level) from an entry like 'SF99952 - 01'."""
    m = _PTF_TOKEN.match(ptf_entry or "")
    return m.group(0).upper() if m else (ptf_entry or "").strip()


def _collect_links(row: List[Dict[str, Any]], column_indices: List[int]) -> List[str]:
    """Gather download hrefs from the given row columns, in order, de-duplicated.

    Keeps ``fix-information`` links first but retains any ``http`` link (the
    same fix may be published at a ``/support/pages/...`` URL), so a real link
    is preferred over a synthesized one.
    """
    links: List[str] = []
    for idx in column_indices:
        if 0 <= idx < len(row):
            for href in row[idx].get("links", []):
                h = href.strip()
                if h and "http" in h.lower() and h not in links:
                    links.append(h)
    return links


def _pick_link(
    links: List[str],
    ptf_entry: str,
    synthesize: bool = True,
) -> str:
    """Pick the best download link for a PTF entry; synthesize if needed."""
    if not links:
        if synthesize and ptf_entry:
            return _DEFAULT_PTF_LINK.format(ptf=extract_ptf_base(ptf_entry))
        return ""
    # Prefer a canonical fix-information URL when one is present.
    for l in links:
        if "fix-information" in l.lower():
            return l
    return links[0]


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

    Detection is *link-first* to avoid the common ambiguity where the words
    'PTF' and 'Level' appear in non-release headers (e.g. 'Group PTF - Level',
    'PTF Download Link'). The link column is located first, then the release
    column, then the PTF column from what remains -- each using header keywords
    and, on ties/fallback, content hints from the data rows.
    """
    n = 3
    pool = [len(r) for r in data_rows]
    if header_texts:
        pool.append(len(header_texts))
    n = max(pool) if pool else 3

    def hdr_has(idx: int, pat: str) -> bool:
        return (
            header_texts is not None
            and 0 <= idx < len(header_texts)
            and bool(re.search(pat, (header_texts[idx] or "").lower()))
        )

    def col_has(idx: int, pred) -> bool:
        return any(0 <= idx < len(r) and pred(_cell_text(r[idx])) for r in data_rows)

    has_url = lambda t: ("http" in t.lower() or "fix-information" in t.lower())
    has_ptf = lambda t: bool(_split_ptfs(t))
    has_release = lambda t: bool(re.search(r"\d+\.\d+", t))

    # 1) Link column: an explicit 'download' header (strongest), else 'link/url',
    #    else any column whose content looks like a URL.
    link_col = next((i for i in range(n) if hdr_has(i, r"download")), None)
    if link_col is None:
        link_col = next((i for i in range(n) if hdr_has(i, r"link|url")), None)
    if link_col is None:
        link_col = next((i for i in range(n) if col_has(i, has_url)), n - 1)
    link_col = n - 1 if link_col is None or link_col < 0 or link_col >= n else link_col

    # 2) Release column: header 'release'/'version' OR version-bearing content,
    #    never the link column.
    release_col = next((i for i in range(n) if i != link_col and hdr_has(i, r"release|version")), None)
    if release_col is None:
        release_col = next((i for i in range(n) if i != link_col and col_has(i, has_release)), 0)
    release_col = 0 if release_col is None or release_col >= n else release_col

    # 3) PTF column: header 'ptf'/'number' (never link/release), else PTF content,
    #    else the column after release -- but stay clear of the link column.
    ptf_col = next(
        (i for i in range(n) if i not in (link_col, release_col) and hdr_has(i, r"ptf|number")),
        None,
    )
    if ptf_col is None:
        ptf_col = next(
            (i for i in range(n) if i not in (link_col, release_col) and col_has(i, has_ptf)),
            None,
        )
    if ptf_col is None:
        ptf_col = release_col + 1
        if ptf_col == link_col:
            ptf_col = link_col - 1
    ptf_col = n - 1 if ptf_col is None or ptf_col >= n else ptf_col
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


# A CVE id like CVE-2019-9517, used as the row label in a transposed "matrix"
# fix table where the releases live in the column headers.
_CVE_TOKEN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
# The IBM X-Force vulnerability id, e.g. .../vulnerabilities/220414. A node page
# that lists no CVE id of its own still links to its X-Force record; we fill the
# CVE-id slot with this when the page has no CVE.
_XFORCE_TOKEN = re.compile(r"xforce\.ibmcloud\.com/vulnerabilities/(\d+)", re.IGNORECASE)
# Number of version-bearing *columns* that must be present to treat a fix table
# as transposed (releases in the headers instead of the data rows).
_MATRIX_MIN_VERSION_COLS = 2


def extract_cve(text: str) -> str:
    """Return the first CVE id in a cell label (e.g. 'CVE-2019-9517'), else ''."""
    m = _CVE_TOKEN.search(text or "")
    return m.group(0).upper() if m else ""


def extract_xforce_id(html: str) -> str:
    """Return the IBM X-Force vulnerability id embedded in a node page.

    A node page that names no CVE still links to an X-Force record such as
    ``https://exchange.xforce.ibmcloud.com/vulnerabilities/220414``; this returns
    the bare id (``'220414'``), or ``''`` when none is present.
    """
    m = _XFORCE_TOKEN.search(html or "")
    return m.group(1) if m else ""


def xforce_url_for(xforce_id: str) -> str:
    """Build the canonical X-Force record URL for an id, or ''."""
    return f"https://exchange.xforce.ibmcloud.com/vulnerabilities/{xforce_id}" if xforce_id else ""


def _has_version(text: str) -> bool:
    return bool(_VERSION.search(text or ""))


def _find_matrix_header(
    rows: List[List[Dict[str, Any]]],
) -> Tuple[Optional[int], Optional[List[Dict[str, Any]]]]:
    """Detect a *transposed* Remediation/Fixes table and return its header row.

    Some node pages (e.g. 1097703) lay the fix table out as a matrix: the column
    headers are IBM i releases (``IBM i 7.4 | IBM i 7.3 | IBM i 7.2``) and each
    data row starts with a row label such as a CVE id, the remaining cells
    holding the PTF (or ``Not affected``) for that release -- the opposite of the
    usual orientation. The signal is a row whose non-label columns (col >= 1)
    carry at least two version tokens, since the usual case keeps versions in the
    data rows, not in the headers.

    :return: ``[index, row]`` of the matrix header, or ``[None, None]``.
    """
    for i, r in enumerate(rows):
        vcols = [j for j in range(1, len(r)) if _has_version(_cell_text(r[j]))]
        if len(vcols) >= _MATRIX_MIN_VERSION_COLS and i < len(rows) - 1:
            return i, r
    return None, None


def _strip_version_label(text: str) -> str:
    """Turn a matrix header such as 'IBM i 7.4' into a product label 'IBM i'."""
    h = re.sub(_VERSION, " ", text or "")
    h = re.sub(r"\brelease\b|\bversion(?:s)?\b", " ", h, flags=re.IGNORECASE)
    h = re.sub(r"[()]", " ", h)
    h = re.sub(r"\s+", " ", h).strip()
    return h


def _matrix_release_columns(
    header_row: List[Dict[str, Any]],
) -> Tuple[Dict[int, str], str, str]:
    """Map each version-bearing header column to its release, product and sw_lvl.

    Returns ``[col_to_release, product, sw_lvl]`` where each key is a column
    index (>=1) whose header names an IBM i release.
    """
    col_to_release: Dict[int, str] = {}
    product = ""
    sw_lvl = ""
    for j in range(1, len(header_row)):
        text = _cell_text(header_row[j])
        rels = extract_versions(text)
        if rels:
            col_to_release[j] = rels[0]
            sw = _extract_sw_lvl([text])
            if sw and not sw_lvl:
                sw_lvl = sw
            if not product:
                product = _strip_version_label(text)
    return col_to_release, product, sw_lvl


def _record(
    node: str,
    release: str,
    sw_lvl: str,
    product: str,
    ptf: str,
    link: str,
    *,
    field_cve_id: str = "",
    field_x_force_id: str = "",
    field_x_force_url: str = "",
) -> Dict[str, Any]:
    rec = {
        "node": node,
        "product": product,
        "ibm_i_release": release,
        "sw_lvl": sw_lvl,
        "ptf_number": ptf,
        "download_link": link,
    }
    # Optional identifiers are only attached when actually learned, so the
    # canonical 6-column PTF records stay unchanged for the common case.
    if field_cve_id:
        rec["field_cve_id"] = field_cve_id
    if field_x_force_id:
        rec["field_x_force_id"] = field_x_force_id
    if field_x_force_url:
        rec["field_x_force_url"] = field_x_force_url
    return rec


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

    each affected OS release in a cell (e.g. '7.4 7.3 7.2') is expanded into a
    dedicated record per version, and each record's ``ptf_number`` keeps any
    trailing PTF level (e.g. 'SF99952 - 01'). The result is one record per
    (node, version, PTF) pair, de-duplicated.

    Two extra cases are also handled:

    * **Transposed "matrix" tables** (e.g. node 1097703): the fix columns are the
      IBM i releases in the *header* (``IBM i 7.4 | IBM i 7.3 | IBM i 7.2``) and
      each data row begins with a row label such as a CVE id. Such a table is
      auto-detected and each non-'Not affected' cell is expanded into a record
      carrying its row's CVE id in ``field_cve_id``.
    * **Pages that name no CVE** (e.g. 6591307, 6551988): the IBM X-Force
      vulnerability id from the page is attached as ``field_x_force_id`` /
      ``field_x_force_url`` so callers can fill an empty CVE-id slot.
    """
    node = str(node_id).strip()
    extractor = _RemediationExtractor()
    extractor.feed(html)
    extractor.close()

    # A page that names no CVE still links to its X-Force record; we surface the
    # id on every record it produces so callers can fill an empty CVE-id slot.
    x_force_id = extract_xforce_id(html)
    x_force_url = xforce_url_for(x_force_id)

    records: List[Dict[str, Any]] = []
    seen: set = set()

    for table_rows in extractor.tables:
        if not table_rows:
            continue

        # --- transposed "matrix" fix table: releases in the column headers, the
        # first data column a per-row label such as a CVE id, the remaining
        # columns holding that release's PTF (or 'Not affected'). Detected and
        # handled separately, then skipped from the normal (row) path.
        m_idx, m_hdr = _find_matrix_header(table_rows)
        if m_hdr is not None:
            col_to_release, matrix_product, matrix_sw = _matrix_release_columns(m_hdr)
            if col_to_release:
                for r in table_rows:
                    if r is m_hdr:
                        continue
                    if not any(_cell_text(c) for c in r):
                        continue
                    cve = extract_cve(_cell_text(r[0])) if r else ""
                    for j, release in col_to_release.items():
                        ptf_raw = _cell_text(r[j]) if j < len(r) else ""
                        if not ptf_raw.strip() or "not affected" in ptf_raw.lower():
                            continue
                        for ptf in extract_ptf_entries(ptf_raw):
                            links = _collect_links(r, [j])
                            link = _pick_link(links, ptf, synthesize=synthesize_links)
                            key = (node, cve, release, matrix_sw, ptf, link)
                            if key in seen:
                                continue
                            seen.add(key)
                            records.append(
                                _record(
                                    node, release, matrix_sw, matrix_product, ptf, link,
                                    field_cve_id=cve,
                                    field_x_force_id=x_force_id,
                                    field_x_force_url=x_force_url,
                                )
                            )
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
            rel_raw = _cell_text(r[release_col]) if release_col < len(r) else ""
            ptf_raw = _cell_text(r[ptf_col]) if ptf_col < len(r) else ""
            links = _collect_links(r, [link_col, ptf_col, release_col])
            versions = normalize_release(rel_raw)
            ptf_entries = extract_ptf_entries(ptf_raw)

            has_content = bool(versions and versions[0]) or bool(ptf_entries) or bool(links)
            if not has_content:
                continue

            if not ptf_entries:
                # A release/fix row with no concrete PTF (e.g. 'refer to ...').
                if not include_empty:
                    continue
                link = _pick_link(links, "", synthesize=synthesize_links)
                base_release = versions[0]
                key = (node, base_release, sw_lvl, "", link)
                if key not in seen:
                    seen.add(key)
                    records.append(
                        _record(node, base_release, sw_lvl, product, "", link,
                                field_x_force_id=x_force_id,
                                field_x_force_url=x_force_url,
                        )
                    )
                continue

            n_links = len(links)
            # One dedicated record per OS release, crossed with each PTF in the
            # row; links are matched to PTFs positionally, falling back to a
            # shared link or a synthesized URL.
            for release in versions:
                for i, ptf in enumerate(ptf_entries):
                    if i < n_links:
                        link = links[i]
                    elif n_links:
                        link = links[-1]
                    else:
                        link = _pick_link(links, ptf, synthesize=synthesize_links)
                    key = (node, release, sw_lvl, ptf, link)
                    if key in seen:
                        continue
                    seen.add(key)
                    records.append(
                        _record(node, release, sw_lvl, product, ptf, link,
                                field_x_force_id=x_force_id,
                                field_x_force_url=x_force_url,
                        )
                    )

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

    As a side effect, any entry that names **no CVE id** has its ``field_cve_id``
    (and ``field_x_force_url``) backfilled in place from the node page's
    X-Force vulnerability id, so a no-CVE node (e.g. 6591307) still yields a
    non-empty identifier in the joined output.

    :param entries: Bulletin entries (from :func:`extract_table_entries`);
        backfilled in place when they lack a CVE id.
    :param log: Optional callable receiving one progress line per node.
    :return: ``(ptf_records, stats)`` where ``stats`` counts nodes fetched,
        nodes failed, and records produced.
    """
    all_records: List[Dict[str, Any]] = []
    seen_nodes: set = set()
    xforce_by_node: Dict[str, str] = {}
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
            xfid = extract_xforce_id(page)
            if xfid:
                xforce_by_node[nid] = xfid
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

    # Backfill no-CVE entries from the X-Force id found on the node page, so a
    # node without a CVE still carries an identifier in the joined output.
    for e in entries:
        if str(e.get("field_cve_id") or "").strip():
            continue
        xfid = xforce_by_node.get(str(e.get("nid") or "").strip())
        if xfid:
            e["field_cve_id"] = xfid
            if not str(e.get("field_x_force_url") or "").strip():
                e["field_x_force_url"] = xforce_url_for(xfid)

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
    "field_x_force_url",
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

    The CVE id on the output row is chosen so that:
      * when a PTF record carries its own ``field_cve_id`` (the row label of a
        transposed fix table), only the bulletin entry that shares *that* CVE is
        paired, so the PTF stays attached to the right vulnerability;
      * when a PTF record has no CVE but a node-level ``field_x_force_id`` was
        found on a no-CVE page, that id fills the ``field_cve_id`` slot, with the
        matching ``field_x_force_url``.

    :param bullets: Bulletin entries (from :func:`extract_table_entries`), each
        carrying an ``nid``.
    :param ptfs: PTF records (from :func:`parse_remediation_ptfs`); may carry
        ``field_cve_id`` / ``field_x_force_id`` / ``field_x_force_url``.
    :return: Flat, joined rows ready for CSV/JSON output.
    """
    by_node: Dict[str, List[Dict[str, Any]]] = {}
    for b in bullets:
        nid = str(b.get("nid") or "").strip()
        if nid:
            by_node.setdefault(nid, []).append(b)

    ptf_part = lambda p: {  # noqa: E731  closure kept for readability
        "product": p.get("product", ""),
        "ibm_i_release": p.get("ibm_i_release", ""),
        "sw_lvl": p.get("sw_lvl", ""),
        "ptf_number": p.get("ptf_number", ""),
        "download_link": p.get("download_link", ""),
    }

    rows: List[Dict[str, Any]] = []
    for p in ptfs:
        node = str(p.get("node") or "")
        p_cve = str(p.get("field_cve_id") or "").strip()
        p_xfid = str(p.get("field_x_force_id") or "").strip()
        p_xfurl = str(p.get("field_x_force_url") or "").strip()
        matched = by_node.get(node)

        if not matched:
            row = {
                "node": node,
                "field_cve_id": p_cve or p_xfid,
                "field_x_force_url": p_xfurl,
                "field_product": "",
                "field_cvss_base_score": "",
                "field_pub_date": "",
                "bulletin_url": "",
            }
            row.update(ptf_part(p))
            rows.append(row)
            continue

        # A PTF record that carries its own CVE (transposed-table row) is paired
        # only with bulletin entries that share that CVE, falling back to all
        # entries for the node when none match (keeps the data, never drops it).
        if p_cve:
            wanted = p_cve.lower()
            cands = [b for b in matched if str(b.get("field_cve_id") or "").strip().lower() == wanted]
            if not cands:
                cands = matched
        else:
            cands = matched

        for b in cands:
            cve = p_cve or str(b.get("field_cve_id") or "").strip() or p_xfid
            xfurl = str(b.get("field_x_force_url") or "").strip() or p_xfurl
            row = {
                "node": node,
                "field_cve_id": cve,
                "field_x_force_url": xfurl,
                "field_product": str(b.get("field_product") or ""),
                "field_cvss_base_score": str(b.get("field_cvss_base_score") or ""),
                "field_pub_date": str(b.get("field_pub_date") or ""),
                "bulletin_url": str(b.get("bulletin_url") or ""),
            }
            row.update(ptf_part(p))
            rows.append(row)
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
