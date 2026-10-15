# IBM Security Bulletin CVE Extractor

A Python application and library to extract all CVE entries and bulletin records from the datatable on the [IBM Product Security Central Bulletins page](https://www.ibm.com/support/pages/bulletin/).

## Background & Architecture

The IBM Security Bulletins page (`https://www.ibm.com/support/pages/bulletin/`) is a client-side rendered Single-Page Application (SPA) built with Vue.js and jQuery DataTables. The table displayed on the page (`#datatable`) is dynamically populated on load from IBM's backend API:

```
GET https://www.ibm.com/support/pages/securityapp/api/site/datalist?offset=0&limit=1000
```

This application queries the endpoint directly with appropriate browser headers and SSL handling, extracting the raw data records (`results.top_records`) that populate the HTML datatable. It also supports extracting the complete list of 24,000+ CVE identifiers indexed by IBM Support (`results.cve_ids`).

**Key Highlights:**
- **Zero Third-Party Dependencies Required**: Runs out of the box with standard Python 3.9+ (`urllib`, `json`, `csv`, `ssl`, etc.).
- **macOS & Linux SSL Resilience**: Automatically resolves SSL certificate issues common in macOS environments.
- **Multiple Output Formats**: Supports `json` (parsed datatable entries), `raw` (complete unaltered IBM API response), `csv`, and human-readable terminal `table`.
- **Search & Filter**: Built-in filtering by CVE ID, product name, severity, or general query.
- **CLI & Python Library**: Can be executed directly via `python3 main.py`, installed as a CLI (`ibm-bulletin`), or imported into Python scripts.

---

## Quick Start

### 1. Run Directly (No installation needed)

```bash
# Print first 5 CVE entries in formatted JSON
### 1. Run Directly (No installation needed)

```bash
# Search for product bulletins (e.g. 'IBM i' or 'AIX')
python3 main.py "IBM i" --limit 5 --format table
python3 main.py "AIX" --limit 5 --format table

# Print first 5 landing page CVE entries in formatted JSON
python3 main.py --limit 5

# View as an ASCII table directly in your terminal
python3 main.py --format table --limit 10

# Export all datatable entries to a CSV file
python3 main.py --format csv -o ibm_cves.csv

# Export complete raw JSON response from IBM
python3 main.py --format raw -o ibm_bulletins_raw.json
```

### 2. Install as a Command-Line Tool

```bash
pip install .
ibm-bulletin "IBM i" --format table --limit 10
```

---

## Command-Line Usage

```text
usage: main.py [search_query] [-s SEARCH] [-q QUERY] [-f {json,raw,csv,table,sqlite}]
               [-d DB] [--table-name NAME] [-o OUTPUT] [-n LIMIT] [--all-cves]
               [--cve CVE] [--product PRODUCT] [--severity SEVERITY]
               [--filter FILTER] [--summary] [--no-enrich] [--indent INDENT]
               [--api-url API_URL] [--insecure] [--remediation] [--delay SECS]
               [--include-empty-fixes] [--synthesize-links|--no-synthesize-links]
               [--flat-csv CSV]
```

A dedicated entry point `main_fixes.py` runs the same CLI but is aimed at the
Remediation/Fixes PTF workflow described below.

### Options

| Flag / Parameter | Description |
|---|---|
| `search_query` | Positional search query parameter (e.g. `"IBM i"` or `"AIX"`) |
| `-s`, `--search`, `-q`, `--query` | Search query parameter to query IBM backend search API |
| `-f`, `--format` | Output format: `json` (default), `raw`, `csv`, `table`, `sqlite` |
| `-o`, `--output` | Write output to a file instead of standard output |
| `-n`, `--limit` | Limit the number of records returned |
| `--all-cves` | Extract the full list of indexed CVE IDs |
| `--cve` | Filter records by CVE ID substring (e.g. `CVE-2026`) |
| `--product` | Filter records by product name (e.g. `Guardium`, `MQ`, `Db2`) |
| `--severity` | Filter records by severity level (`Critical`, `High`, `Medium`, `Low`) |
| `--filter` | Additional local filter across title, product, and CVE |
| `--summary` | Print summary statistics to `stderr` |
| `--no-enrich` | Do not add generated convenience URLs (`bulletin_url`) |
| `--indent` | Number of spaces for JSON indentation (default: `2`, `0` for compact) |
| `--api-url` | Override the default IBM API endpoint URL |
| `--insecure` | Disable SSL certificate validation |
| `--remediation` | After extracting entries, fetch each node page and parse the Remediation/Fixes table into one record per (release, PTF) |
| `--delay SECS` | Seconds to wait between node fetches (default `0.2`) |
| `--include-empty-fixes` | Also keep remediation rows that have a release but no concrete PTF number |
| `--synthesize-links` / `--no-synthesize-links` | Build a `fix-information` download URL from the PTF number when a row has no link (default: synthesize) |
| `--flat-csv CSV` | Also write a fully joined CSV (bulletin context + PTF columns) |
| `-d`, `--sqlite`, `--db DB` | Write a SQLite database; with `--remediation` it holds **both** `bulletins` and `remediation_ptfs` tables, joinable on `node = nid` |

### Examples

#### Search for "IBM i" or "AIX" Bulletins
```bash
# Search for IBM i bulletins and render as table
python3 main.py "IBM i" --format table --limit 10

# Search for AIX bulletins with Critical severity
python3 main.py "AIX" --severity "Critical" --format table

# Search using the -s / --search flag
python3 main.py -s "IBM i" --limit 5

# Export all AIX CVE entries to CSV
python3 main.py "AIX" --format csv -o aix_cves.csv
```

#### Filter Landing Page Table by Product and Severity
```bash
python3 main.py --product "Guardium" --severity "Critical" --format table
```

#### Extract Full List of Indexed CVE IDs
```bash
# Extract the first 20 CVE IDs
python3 main.py --all-cves --limit 20

# Search for specific CVEs in the full 24k+ CVE index
python3 main.py --all-cves --cve "CVE-2026" --limit 50
```

#### Pipe Clean JSON to `jq`
```bash
python3 main.py "AIX" --limit 10 | jq '.[].field_cve_id'
```

---

## Remediation/Fixes PTF Extraction

For each matching CVE/bulletin, the node page
(`https://www.ibm.com/support/pages/node/<nid>`, e.g. `…/node/7288323`) carries a
**Remediation/Fixes** table mapping each affected product release to its PTF
numbers and download links. `--remediation` fetches each node page and expands
that table into **one record per (release, PTF)**, e.g.::

    node, ibm_i_release, sw_lvl, ptf_number, download_link
    7288323, 7.6, 5770-SS1, SJ11497, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11497
    7288323, 7.5, 5770-SS1, SJ11498, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11498
    7288323, 7.4, 5770-SS1, SJ11499, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11499
    7288323, 7.3, 5770-SS1, SJ11500, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11500

Notes
- `--remediation` applies to the **entry** path (a bulletin/search fetch); combine
  it with `--search`/`--product`/`--severity`/`--limit` to keep the node fetches
  bounded. It runs after the entry filters are applied.
- `sw_lvl` is read from the PTF column header token (e.g. `5770-SS1` /
  `5770-TC1`); it is empty for tables without one.
- When a row has a PTF but no link, the URL is synthesized as
  `…/fix-information?legacy=<PTF>` (disable with `--no-synthesize-links`).
- `--include-empty-fixes` also keeps release rows that point to a fix
  procedure textually but list no concrete PTF number.

### Data-quality guarantees
- **One record per OS release.** A release cell that lists several versions
  (`7.4 7.3 7.2`) is split into a dedicated record **per version**; each version
  is paired with every PTF in the row (products list one PTF that covers all
  listed releases, or several PTFs per release). The `ibm_i_release` value is
  always a clean version number (`7.6`, `7.4.1`, …) — `V7R2` normalized to `7.2`.
- **PTF level is kept.** A `PTF - Level` value such as `SF99952 - 01` stays
  intact in `ptf_number` (`… - 01`), and is *not* leaked into the release field.
- **Robust column detection.** The PTF and download columns are located by a
  link-first heuristic that ignores the word `Level`/`PTF` appearing in
  non-release headers (e.g. `Group PTF - Level`, `PTF Download Link`), which is
  the usual source of mis-parsed rows.
- **Real download links are captured**, whether they are the canonical
  `…/fix-information?legacy=<PTF>` or an IBM `…/support/pages/<ptf>-…` URL; only
  when there is no link at all is one synthesized.

Concrete examples (from live node pages):
```
# node 7242043 — a multi-release cell expands to one record per version
7242043, 7.4, 5733-SC1, SJ06726, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ06726
7242043, 7.3, 5733-SC1, SJ06726, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ06726
7242043, 7.2, 5733-SC1, SJ06726, https://www.ibm.com/mysupport/s/fix-information?legacy=SJ06726

# node 6589203 — the PTF level is kept and the release is a clean version
6589203, 7.5, , SF99952 - 01, https://www.ibm.com/support/pages/sf99952-750-ibm-http-server-i-level-1
6589203, 7.4, , SF99662 - 20, https://www.ibm.com/support/pages/sf99662-740-ibm-http-server-i-level-20
6589203, 7.3, , SF99722 - 39, https://www.ibm.com/support/pages/sf99722-730-ibm-http-server-i-level-39
```

### Two-table model (join on `node = nid`)

The bulletin context and the PTF data are kept in **two tables** and joined on
the node id:

| Table | Source | Key fields |
|---|---|---|
| `bulletins` | bulletin page / API | `nid`, `field_cve_id`, `field_product`, `field_cvss_base_score`, `field_pub_date`, `bulletin_url` |
| `remediation_ptfs` | node page Remediation/Fixes table | `node`, `product`, `ibm_i_release`, `sw_lvl`, `ptf_number`, `download_link` |

Pass `-d`/`--sqlite` together with `--remediation` to write **both** tables into
a single database, then join in SQL:

```sql
SELECT b.nid, b.field_cve_id, r.ibm_i_release, r.sw_lvl, r.ptf_number, r.download_link
FROM bulletins b
JOIN remediation_ptfs r ON b.nid = r.node;
```

#### Examples
```bash
# PTF rows for IBM i bulletins, shown as a table (stdout)
python3 main_fixes.py "IBM i" --remediation --format table --limit 40

# Persist both tables to one DB and emit a fully-joined flat CSV
python3 main_fixes.py "IBM i" --remediation -d ibm.db --flat-csv fixes.csv
python3 main_fixes.py "IBM i" --remediation --summary -d ibm_i.db --flat-csv ibm_i_ptfs.csv >/dev/null

# As JSON for downstream processing
python3 main_fixes.py "IBM i" --remediation -f json --limit 50 -o ptfs.json
```

The same operations are available as a library:

```python
from ibm_security_bulletin import (
    fetch_raw_bulletin_data,
    extract_table_entries,
    filter_entries,
    collect_ptfs_for_entries,
    export_to_sqlite,
    export_ptfs_to_sqlite,
    build_flat_join,
)

data = fetch_raw_bulletin_data(search_query="IBM i")
entries = filter_entries(extract_table_entries(data), product="IBM i")
ptfs, stats = collect_ptfs_for_entries(entries)   # fetches each node page

export_to_sqlite(entries, db_path="ibm.db", table_name="bulletins")
export_ptfs_to_sqlite(ptfs, db_path="ibm.db", table_name="remediation_ptfs")

flat = build_flat_join(entries, ptfs)   # bulletin context + PTF per row
```

## Python Library Usage

You can import `ibm_security_bulletin` in your Python code:

```python
from ibm_security_bulletin import (
    fetch_raw_bulletin_data,
    extract_table_entries,
    extract_all_cve_ids,
    filter_entries,
)

# 1. Fetch raw API payload
data = fetch_raw_bulletin_data()

# 2. Extract records that build the HTML datatable
records = extract_table_entries(data)
print(f"Retrieved {len(records)} datatable records.")

for entry in records[:3]:
    print(f"CVE: {entry['field_cve_id']}")
    print(f"Severity: {entry['field_cvss_base_score']}")
    print(f"Product: {entry['field_product']}")
    print(f"Bulletin URL: {entry['bulletin_url']}")
    print("-" * 40)

# 3. Filter entries in Python
critical_guardium = filter_entries(records, product="Guardium", severity="Critical")
print(f"Found {len(critical_guardium)} Critical Guardium vulnerabilities.")

# 4. Extract all 24,000+ indexed CVE identifiers
all_cves = extract_all_cve_ids(data)
print(f"Total indexed CVEs across IBM: {len(all_cves)}")
```

---

## Data Fields

Each entry that populates the HTML datatable contains the following raw fields:

| Field | Description | Example |
|---|---|---|
| `nid` | Bulletin Node ID | `"7289064"` |
| `bulletin_url` | Full URL to IBM Security Bulletin | `"https://www.ibm.com/support/pages/node/7289064"` |
| `title` | Security Bulletin Title | `"Multiple vulnerabilities in IBM MQ Operator..."` |
| `field_cve_id` | Associated CVE identifier | `"CVE-2018-16487"` |
| `field_product` | Affected Product Name | `"IBM MQ container software"` |
| `field_cvss_base_score` | CVSS Severity Level | `"Critical"`, `"High"`, `"Medium"`, `"Low"` |
| `field_cvss_base_score_color`| CSS class for severity badge | `"sev_critical"`, `"sev_high"` |
| `field_pub_date` | Bulletin publication date | `"2026-09-23"` |
| `field_x_force_url` | Link to CVE record / X-Force | `"https://www.cve.org/CVERecord?id=CVE-2018-16487"` |
| `field_oc_code` | IBM Offering Component code | `"SSFE2G"` |
| `field_offering_pid_number` | IBM Product PID number | `""` |
| `field_cvss_desc` | Detailed CVSS description | `""` |
| `field_reported_date` | Date vulnerability was reported | `""` |

---

## Running Tests

Run the test suite using `unittest`:

```bash
python3 -m unittest discover tests
```
