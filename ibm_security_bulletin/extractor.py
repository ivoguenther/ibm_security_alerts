"""
Core extraction logic for IBM Security Bulletins datatable.
"""

from __future__ import annotations

import json
import logging
import ssl
import sys
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "https://www.ibm.com/support/pages/securityapp/api/site/datalist?offset=0&limit=1000"
DEFAULT_SEARCH_URL = "https://www.ibm.com/support/pages/securityapp/api/search"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
BASE_BULLETIN_URL = "https://www.ibm.com/support/pages/node/"
NODE_URL_TEMPLATE = "https://www.ibm.com/support/pages/node/{node}"


def _create_ssl_context(insecure: bool = False) -> ssl.SSLContext:
    """
    Create an SSL context. On macOS and some Linux environments where system
    Python may lack configured root certificates, tries standard methods and
    falls back cleanly if needed.
    """
    if insecure:
        if hasattr(ssl, "_create_unverified_context"):
            return ssl._create_unverified_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    try:
        # Check if certifi is available
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    try:
        return ssl.create_default_context()
    except Exception:
        if hasattr(ssl, "_create_unverified_context"):
            return ssl._create_unverified_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def build_headers(
    accept: str, user_agent: str = DEFAULT_USER_AGENT
) -> Dict[str, str]:
    """
    Builds the shared browser-like request headers used for all IBM requests.

    :param accept: The ``Accept`` header value (JSON for the API, HTML for nodes).
    :param user_agent: User-Agent header string.
    :return: Dictionary of HTTP headers.
    """
    return {
        "User-Agent": user_agent,
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.ibm.com/support/pages/bulletin/",
    }


def http_fetch_text(
    target_url: str,
    timeout: int = 60,
    user_agent: str = DEFAULT_USER_AGENT,
    accept: str = "application/json, text/plain, */*",
    insecure: bool = False,
) -> str:
    """
    Fetches a URL and returns the decoded response body as text.

    Uses the browser-like headers and SSL handling shared across the extractor.
    On a ``CERTIFICATE_VERIFY_FAILED`` error (common on macOS/Linux with an
    unconfigured system Python) it transparently retries with an unverified
    context, unless ``insecure`` was already requested.

    :param target_url: Target URL to fetch.
    :param timeout: Request timeout in seconds.
    :param user_agent: User-Agent header string.
    :param accept: ``Accept`` header value.
    :param insecure: Whether to disable SSL certificate verification.
    :return: Decoded response body.
    """
    headers = build_headers(accept, user_agent=user_agent)
    ctx = _create_ssl_context(insecure=insecure)

    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset)
    except urllib.error.URLError as e:
        # If default certificate verification failed on macOS, attempt automatic fallback
        if not insecure and "CERTIFICATE_VERIFY_FAILED" in str(e):
            logger.warning(
                "System SSL certificate verification failed. Retrying with unverified context."
            )
            fallback_ctx = _create_ssl_context(insecure=True)
            fallback_req = urllib.request.Request(target_url, headers=headers)
            with urllib.request.urlopen(
                fallback_req, context=fallback_ctx, timeout=timeout
            ) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read().decode(charset)
        raise


def fetch_raw_bulletin_data(
    api_url: Optional[str] = None,
    search_query: Optional[str] = None,
    timeout: int = 60,
    user_agent: str = DEFAULT_USER_AGENT,
    insecure: bool = False,
) -> Dict[str, Any]:
    """
    Fetches the raw JSON payload from IBM Security Bulletin API.

    :param api_url: Custom API endpoint URL. If None, uses DEFAULT_SEARCH_URL
                    when search_query is supplied, or DEFAULT_API_URL otherwise.
    :param search_query: Search query parameter (e.g., 'IBM i' or 'AIX').
    :param timeout: Request timeout in seconds.
    :param user_agent: User-Agent header string.
    :param insecure: Whether to disable SSL certificate verification.
    :return: Parsed JSON response as a dictionary.
    """
    import urllib.parse

    if api_url is None:
        if search_query and search_query.strip():
            params = urllib.parse.urlencode({"q": search_query.strip()})
            target_url = f"{DEFAULT_SEARCH_URL}?{params}"
        else:
            target_url = DEFAULT_API_URL
    else:
        if search_query and search_query.strip() and "?" not in api_url:
            params = urllib.parse.urlencode({"q": search_query.strip()})
            target_url = f"{api_url}?{params}"
        else:
            target_url = api_url

    raw_body = http_fetch_text(
        target_url,
        timeout=timeout,
        user_agent=user_agent,
        accept="application/json, text/plain, */*",
        insecure=insecure,
    )
    return json.loads(raw_body)


def extract_table_entries(
    raw_data: Dict[str, Any], enrich_urls: bool = True
) -> List[Dict[str, Any]]:
    """
    Extracts the list of records that populate the HTML datatable.

    Handles both:
    1. /site/datalist response: records in `results.top_records`
    2. /search?q=... response: records in `results` list

    :param raw_data: Dictionary returned by fetch_raw_bulletin_data().
    :param enrich_urls: If True, adds `bulletin_url` for convenience.
    :return: List of record dictionaries.
    """
    results = raw_data.get("results", {})
    if isinstance(results, dict):
        records = results.get("top_records", [])
    elif isinstance(results, list):
        records = results
    else:
        records = []

    if not enrich_urls:
        return list(records)

    enriched = []
    for item in records:
        record_copy = dict(item)
        nid = str(record_copy.get("nid", "")).strip()
        if nid:
            record_copy["bulletin_url"] = f"{BASE_BULLETIN_URL}{nid}"
        else:
            record_copy["bulletin_url"] = ""
        enriched.append(record_copy)

    return enriched


def extract_all_cve_ids(raw_data: Dict[str, Any]) -> List[str]:
    """
    Extracts the complete list of all CVE IDs indexed by IBM.
    Supports both datalist responses (containing `results.cve_ids`) and
    search responses (extracting CVEs from the `results` list).

    :param raw_data: Dictionary returned by fetch_raw_bulletin_data().
    :return: List of clean CVE ID strings.
    """
    results = raw_data.get("results", {})
    if isinstance(results, dict):
        raw_cves = results.get("cve_ids", [])
    elif isinstance(results, list):
        raw_cves = [r.get("field_cve_id") for r in results if isinstance(r, dict)]
    else:
        raw_cves = []

    # Filter empty or null entries
    seen = set()
    cleaned = []
    for cve in raw_cves:
        if cve and isinstance(cve, str):
            cve_str = cve.strip()
            if cve_str and cve_str not in seen:
                seen.add(cve_str)
                cleaned.append(cve_str)
    return cleaned


def filter_entries(
    entries: List[Dict[str, Any]],
    cve: Optional[str] = None,
    product: Optional[str] = None,
    severity: Optional[str] = None,
    query: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Filters datatable entries based on search criteria.
    """
    filtered = entries

    if cve:
        cve_lower = cve.strip().lower()
        filtered = [
            e
            for e in filtered
            if cve_lower in str(e.get("field_cve_id", "")).lower()
        ]

    if product:
        prod_lower = product.strip().lower()
        filtered = [
            e
            for e in filtered
            if prod_lower in str(e.get("field_product", "")).lower()
        ]

    if severity:
        sev_lower = severity.strip().lower()
        filtered = [
            e
            for e in filtered
            if sev_lower in str(e.get("field_cvss_base_score", "")).lower()
        ]

    if query:
        q_lower = query.strip().lower()
        filtered = [
            e
            for e in filtered
            if (
                q_lower in str(e.get("title", "")).lower()
                or q_lower in str(e.get("field_cve_id", "")).lower()
                or q_lower in str(e.get("field_product", "")).lower()
                or q_lower in str(e.get("field_cvss_base_score", "")).lower()
            )
        ]

    return filtered


def export_to_sqlite(
    entries: List[Dict[str, Any]],
    db_path: str,
    table_name: str = "bulletins",
) -> int:
    """
    Exports bulletin entries to a SQLite database.

    :param entries: List of bulletin entry dictionaries.
    :param db_path: File path to the SQLite database.
    :param table_name: Table name to create/insert into (default: 'bulletins').
    :return: Number of records inserted or updated.
    """
    import os
    import sqlite3

    dir_name = os.path.dirname(db_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    safe_table = "".join(c for c in table_name if c.isalnum() or c == "_")
    if not safe_table:
        safe_table = "bulletins"

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {safe_table} (
                nid TEXT,
                bulletin_url TEXT,
                title TEXT,
                field_cve_id TEXT,
                field_product TEXT,
                field_cvss_base_score TEXT,
                field_cvss_base_score_color TEXT,
                field_pub_date TEXT,
                field_x_force_url TEXT,
                field_oc_code TEXT,
                field_offering_pid_number TEXT,
                field_cvss_desc TEXT,
                field_reported_date TEXT,
                field_section_id TEXT,
                PRIMARY KEY (nid, field_cve_id, field_product)
            )
            """
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_cve ON {safe_table}(field_cve_id)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_product ON {safe_table}(field_product)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_pub_date ON {safe_table}(field_pub_date)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{safe_table}_severity ON {safe_table}(field_cvss_base_score)"
        )

        rows = []
        for e in entries:
            rows.append(
                (
                    str(e.get("nid") or ""),
                    str(e.get("bulletin_url") or ""),
                    str(e.get("title") or ""),
                    str(e.get("field_cve_id") or ""),
                    str(e.get("field_product") or ""),
                    str(e.get("field_cvss_base_score") or ""),
                    str(e.get("field_cvss_base_score_color") or ""),
                    str(e.get("field_pub_date") or ""),
                    str(e.get("field_x_force_url") or ""),
                    str(e.get("field_oc_code") or ""),
                    str(e.get("field_offering_pid_number") or ""),
                    str(e.get("field_cvss_desc") or ""),
                    str(e.get("field_reported_date") or ""),
                    str(e.get("field_section_id") or ""),
                )
            )

        cursor.executemany(
            f"""
            INSERT OR REPLACE INTO {safe_table} (
                nid, bulletin_url, title, field_cve_id, field_product,
                field_cvss_base_score, field_cvss_base_score_color,
                field_pub_date, field_x_force_url, field_oc_code,
                field_offering_pid_number, field_cvss_desc,
                field_reported_date, field_section_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        return len(rows)
    finally:
        conn.close()


def export_cves_to_sqlite(
    cve_ids: List[str],
    db_path: str,
    table_name: str = "cve_ids",
) -> int:
    """
    Exports a list of CVE IDs to a SQLite database.

    :param cve_ids: List of CVE ID strings.
    :param db_path: File path to the SQLite database.
    :param table_name: Table name (default: 'cve_ids').
    :return: Number of records inserted.
    """
    import os
    import sqlite3

    dir_name = os.path.dirname(db_path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)

    safe_table = "".join(c for c in table_name if c.isalnum() or c == "_")
    if not safe_table:
        safe_table = "cve_ids"

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {safe_table} (
                cve_id TEXT PRIMARY KEY
            )
            """
        )
        cursor.executemany(
            f"INSERT OR IGNORE INTO {safe_table} (cve_id) VALUES (?)",
            [(c,) for c in cve_ids if c],
        )
        conn.commit()
        return len(cve_ids)
    finally:
        conn.close()
