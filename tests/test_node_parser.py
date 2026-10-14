"""
Offline tests for the node-page Remediation/Fixes PTF extraction.

These run without network access against a captured node fixture plus small
synthetic HTML fragments.
"""

import os
import re
import sqlite3
import tempfile
import unittest

from ibm_security_bulletin.node_parser import (
    _classify_columns,
    build_flat_join,
    export_ptfs_to_sqlite,
    extract_ptf_base,
    extract_ptf_entries,
    extract_versions,
    fetch_node_html,  # noqa: F401  (imported here to catch import regressions)
    format_flat_csv,
    normalize_release,
    parse_remediation_ptfs,
)
from ibm_security_bulletin.extractor import export_to_sqlite

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "node_7288323.html")


def read_fixture() -> str:
    with open(FIXTURE, encoding="utf-8", errors="replace") as f:
        return f.read()

# A node page with NO Remediation/Fixes table at all.
NO_REMEDIATION = "<html><body><h1>Bulletin</h1><p>No fixes here.</p></body></html>"

# A node page with a Remediation table that holds multiple PTFs + links per cell
# and an HTML-encoded (=) entity in the href.
MULTI_PTF = """
<html><body>
<div class="field--name-field-remediation-fixes field--type-text-long">
  <h2>Remediation/Fixes</h2>
  <table border="1">
    <thead><tr>
      <td>IBM i Release</td>
      <td>5770-SS1 PTF Number(s)</td>
      <td>PTF Download Link(s)</td>
    </tr></thead>
    <tbody>
      <tr>
        <td>7.5</td>
        <td>SJ11498<br />SF10345</td>
        <td>
          <a href="https://www.ibm.com/mysupport/s/fix-information?legacy&#61;SJ11498">sj11498</a>
          <a href="https://www.ibm.com/mysupport/s/fix-information?legacy&#61;SF10345">sf10345</a>
        </td>
      </tr>
    </tbody>
  </table>
</div>
</body></html>
"""

# A release cell lists several OS releases ("7.4 7.3 7.2") with a single PTF.
MULTI_RELEASE = """
<div class="field--name-field-remediation-fixes">
  <table border="1">
    <tr><td>IBM i Release</td><td>5733-SC1 PTF Number</td><td>PTF Download Link</td></tr>
    <tr>
      <td>7.4 7.3 7.2</td>
      <td>SJ06726</td>
      <td><a href="https://www.ibm.com/mysupport/s/fix-information?legacy&#61;SJ06726">SJ06726</a></td>
    </tr>
  </table>
</div>
"""

# 'Level' and 'PTF' appear in non-release headers; the PTF column carries a
# 'PTF - Level' value and the download link is a /support/pages/ URL.
PTF_WITH_LEVEL = """
<div class="field--name-field-remediation-fixes">
  <table border="1">
    <thead><tr>
      <td>IBM i Release</td>
      <td>HTTP Server for i Group PTF - Level</td>
      <td>PTF Download Link(s)</td>
    </tr></thead>
    <tbody>
      <tr>
        <td>7.4</td>
        <td>SF99662 - 20</td>
        <td>
          <a href="https://www.ibm.com/support/pages/sf99662-740-ibm-http-server-i-level-20">SF99662 740 level 20</a>
        </td>
      </tr>
    </tbody>
  </table>
</div>
"""

# Space-separated PTFs for a single version, no explicit links.
CROSS_PRODUCT = """
<div class="field--name-field-remediation-fixes">
  <table border="1">
    <tr><td>IBM i Release</td><td>5770-SS1 PTF(s)</td><td>PTF Download Link(s)</td></tr>
    <tr><td>7.5</td><td>SJ11605 SJ11597</td><td></td></tr>
  </table>
</div>
"""


class TestParseRemediation(unittest.TestCase):
    def test_fixture_produces_expected_ptf_rows(self):
        html = read_fixture()
        recs = parse_remediation_ptfs(html, "7288323")
        self.assertEqual(len(recs), 4)

        expected = {
            r["ptf_number"]: (r["ibm_i_release"], r["sw_lvl"], r["download_link"])
            for r in recs
        }
        self.assertEqual(
            expected["SJ11497"],
            ("7.6", "5770-SS1", "https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11497"),
        )
        self.assertEqual(expected["SJ11498"][0], "7.5")
        self.assertEqual(expected["SJ11499"][0], "7.4")
        self.assertEqual(expected["SJ11500"][0], "7.3")

        for r in recs:
            # The 5 requested columns must be present and the node copied through.
            self.assertEqual(r["node"], "7288323")
            self.assertEqual(r["product"], "IBM i")
            for key in ("node", "ibm_i_release", "sw_lvl", "ptf_number", "download_link"):
                self.assertIn(key, r)

    def test_entity_unescaping_in_link(self):
        html = read_fixture()
        recs = parse_remediation_ptfs(html, "7288323")
        links = {r["ptf_number"]: r["download_link"] for r in recs}
        # &#61; must become '=' in the decoded URL.
        self.assertIn("legacy=SJ11497", links["SJ11497"])
        self.assertNotIn("&#61;", links["SJ11497"])

    def test_multiple_ptfs_split_into_rows(self):
        recs = parse_remediation_ptfs(MULTI_PTF, "1")
        by_ptf = {r["ptf_number"]: r for r in recs}
        self.assertEqual(set(by_ptf), {"SJ11498", "SF10345"})
        self.assertEqual(by_ptf["SJ11498"]["download_link"],
                         "https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11498")
        self.assertEqual(by_ptf["SF10345"]["download_link"],
                         "https://www.ibm.com/mysupport/s/fix-information?legacy=SF10345")
        self.assertEqual(by_ptf["SJ11498"]["sw_lvl"], "5770-SS1")
        self.assertEqual(by_ptf["SF10345"]["sw_lvl"], "5770-SS1")
        self.assertEqual(by_ptf["SJ11498"]["ibm_i_release"], "7.5")

    def test_no_remediation_yields_no_rows(self):
        self.assertEqual(parse_remediation_ptfs(NO_REMEDIATION, "999"), [])

    def test_include_empty_fixes(self):
        html = """
        <div class="field--name-field-remediation-fixes">
          <table border="1">
            <tr><td>IBM i Release</td><td>5770-SS1 PTF Number(s)</td><td>PTF Download Link(s)</td></tr>
            <tr><td>7.2</td><td>Refer to IBM i V7R2 mksysptf</td><td></td></tr>
          </table>
        </div>
        """
        # By default, no concrete PTF -> no rows.
        self.assertEqual(parse_remediation_ptfs(html, "1"), [])
        # With include_empty, the release row survives with an empty PTF.
        recs = parse_remediation_ptfs(html, "1", include_empty=True)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["ibm_i_release"], "7.2")
        self.assertEqual(recs[0]["ptf_number"], "")

    def test_synth_and_no_synth_links(self):
        html = """
        <div class="field--name-field-remediation-fixes">
          <table border="1">
            <tr><td>Release</td><td>PTF(s)</td><td>Link</td></tr>
            <tr><td>7.6</td><td>SJ11497</td><td></td></tr>
          </table>
        </div>
        """
        self.assertEqual(
            parse_remediation_ptfs(html, "1", synthesize_links=True)[0]["download_link"],
            "https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11497",
        )
        self.assertEqual(
            parse_remediation_ptfs(html, "1", synthesize_links=False)[0]["download_link"],
            "",
        )

    def test_multi_release_cell_splits_into_per_version_rows(self):
        # "7.4 7.3 7.2" must become one dedicated record per OS release.
        recs = parse_remediation_ptfs(MULTI_RELEASE, "7242043")
        by_release = {r["ibm_i_release"]: r for r in recs}
        self.assertEqual(set(by_release), {"7.4", "7.3", "7.2"})
        for rel in ("7.4", "7.3", "7.2"):
            r = by_release[rel]
            self.assertEqual(r["ptf_number"], "SJ06726")
            self.assertEqual(r["sw_lvl"], "5733-SC1")
            self.assertEqual(r["download_link"],
                             "https://www.ibm.com/mysupport/s/fix-information?legacy=SJ06726")
        # Crucially: no record leaks the raw multi-release string.
        self.assertFalse(any(" " in r["ibm_i_release"] for r in recs))
        self.assertTrue(all(re.fullmatch(r"\d+\.\d+", r["ibm_i_release"]) for r in recs))

    def test_ptf_level_is_kept_and_classification_is_robust(self):
        # 'Level' and 'PTF' appear in non-release headers; the PTF column carries
        # a 'PTF - Level' value and the link is a /support/pages/ URL.
        recs = parse_remediation_ptfs(PTF_WITH_LEVEL, "6589203")
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["ibm_i_release"], "7.4")
        self.assertEqual(r["ptf_number"], "SF99662 - 20")
        self.assertEqual(r["sw_lvl"], "")  # no 5xxx-XXX token in this header
        # The real /support/pages link is captured, not synthesized.
        self.assertIn("support/pages", r["download_link"])
        self.assertFalse(r["download_link"].startswith("fix-information"))
        # Regression guard: the release column is still col 0.
        release_col, ptf_col, link_col = _classify_columns(
            ["IBM i Release", "HTTP Server for i Group PTF - Level", "PTF Download Link(s)"],
            [[{"text": "7.4", "links": []}, {"text": "SF99662 - 20", "links": []},
              {"text": "SF99662 740", "links": ["https://www.ibm.com/support/pages/x"]}]],
        )
        self.assertEqual((release_col, ptf_col, link_col), (0, 1, 2))

    def test_cross_product_versions_x_ptfs(self):
        # A single version with two space-separated PTFs -> two synthesized rows.
        recs = parse_remediation_ptfs(CROSS_PRODUCT, "1", synthesize_links=True)
        by_ptf = {r["ptf_number"]: r for r in recs}
        self.assertEqual(set(by_ptf), {"SJ11605", "SJ11597"})
        self.assertEqual(all(v["ibm_i_release"] == "7.5" for v in by_ptf.values()), True)
        self.assertEqual(
            by_ptf["SJ11605"]["download_link"],
            "https://www.ibm.com/mysupport/s/fix-information?legacy=SJ11605",
        )

    def test_extraction_helpers(self):
        self.assertEqual(extract_versions("7.4 7.3 7.2"), ["7.4", "7.3", "7.2"])
        self.assertEqual(extract_versions("V7R2"), ["7.2"])
        self.assertEqual(extract_versions("i 8.1"), ["8.1"])
        self.assertEqual(normalize_release("no version token here"), ["no version token here"])
        self.assertEqual(normalize_release(""), [""])
        self.assertEqual(extract_ptf_entries("SF99662 - 20"), ["SF99662 - 20"])
        self.assertEqual(extract_ptf_entries("SJ11497\nSF10345"), ["SJ11497", "SF10345"])
        self.assertEqual(extract_ptf_base("SF99662 - 20"), "SF99662")
        self.assertEqual(extract_ptf_base("SJ11497"), "SJ11497")


class TestPersistenceAndJoin(unittest.TestCase):
    def test_export_and_join(self):
        html = read_fixture()
        ptfs = parse_remediation_ptfs(html, "7288323")
        bullets = [
            {"nid": "7288323", "field_cve_id": "CVE-2024-1", "field_product": "IBM i",
             "field_cvss_base_score": "High", "field_pub_date": "2024-01-01",
             "bulletin_url": "https://www.ibm.com/support/pages/node/7288323"},
            {"nid": "7288323", "field_cve_id": "CVE-2024-2", "field_product": "IBM i",
             "field_cvss_base_score": "Medium", "field_pub_date": "2024-01-01",
             "bulletin_url": "https://www.ibm.com/support/pages/node/7288323"},
            {"nid": "999999", "field_cve_id": "CVE-2024-9", "field_product": "Other",
             "field_cvss_base_score": "Low", "field_pub_date": "2024-01-01",
             "bulletin_url": "https://www.ibm.com/support/pages/node/999999"},
        ]
        db = tempfile.mktemp(suffix=".db")
        try:
            self.assertEqual(export_to_sqlite(bullets, db, "bulletins"), 3)
            self.assertEqual(export_ptfs_to_sqlite(ptfs, db, "remediation_ptfs"), len(ptfs))

            con = sqlite3.connect(db)
            try:
                joined = list(con.execute(
                    "SELECT b.nid, r.ptf_number FROM bulletins b "
                    "JOIN remediation_ptfs r ON b.nid = r.node"
                ))
            finally:
                con.close()
            # 2 bulletins for node 7288323 x 4 PTF rows = 8, node 999999 unmatched.
            self.assertEqual(len(joined), 8)
            self.assertTrue(all(nid == "7288323" for nid, _ in joined))

            flat = build_flat_join(bullets, ptfs)
            # 4 PTF rows x 2 bulletins for node 7288323 = 8. Node 999999 has no
            # PTF rows, so it does NOT appear in the PTF-driven flat join.
            self.assertEqual(len(flat), 8)

            csv_text = format_flat_csv(flat)
            self.assertTrue(csv_text.startswith("node,field_cve_id,"))
            self.assertEqual(csv_text.count("\n") - 1, len(flat))
        finally:
            os.remove(db)

    def test_export_table_name_sanitized(self):
        db = tempfile.mktemp(suffix=".db")
        try:
            # A hostile table name must not cause SQL injection / error.
            n = export_ptfs_to_sqlite(
                [{"node": "1", "ibm_i_release": "7.6", "sw_lvl": "", "ptf_number": "X1",
                  "download_link": "http://x"}],
                db,
                table_name="../../etc/evil;DROP",
            )
            self.assertEqual(n, 1)
            con = sqlite3.connect(db)
            try:
                tables = {r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            finally:
                con.close()
            self.assertNotIn("../../etc/evil;DROP", tables)
        finally:
            os.remove(db)


if __name__ == "__main__":
    unittest.main()
