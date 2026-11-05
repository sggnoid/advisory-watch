"""Tests for watch.py. Run: python3 -m unittest discover -s tests"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import watch  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def fixture(advisory_id):
    return (FIXTURES / f"{advisory_id}.yml").read_text(encoding="utf-8")


def parsed(advisory_id):
    return watch.parse_advisory(advisory_id, fixture(advisory_id))


VALID = """announced: November 03, 2026
impact: high
fixed_in:
- Firefox 200.0
title: {title}
advisories:
  CVE-2026-1000:
    title: A bug
    impact: high
"""


class ParseRealAdvisories(unittest.TestCase):
    def test_firefox_dot_release(self):
        advisory = parsed("mfsa2026-123")
        self.assertEqual(advisory["firefox_version"], "159.0.1")
        self.assertEqual(advisory["impact"], "high")
        self.assertEqual(advisory["cve_count"], 1)
        self.assertFalse(advisory["exploited"])

    def test_critical_impact(self):
        self.assertEqual(parsed("mfsa2026-67")["impact"], "critical")

    def test_esr_only_has_no_firefox_version(self):
        self.assertIsNone(parsed("mfsa2026-120")["firefox_version"])

    def test_thunderbird_only_has_no_firefox_version(self):
        self.assertIsNone(parsed("mfsa2026-121")["firefox_version"])

    def test_mixed_advisory_picks_the_firefox_line(self):
        self.assertEqual(parsed("mfsa2024-51")["firefox_version"], "131.0.2")

    def test_exploited_in_the_wild(self):
        self.assertTrue(parsed("mfsa2024-51")["exploited"])

    def test_mention_of_another_exploit_is_an_accepted_false_alarm(self):
        self.assertTrue(parsed("mfsa2025-19")["exploited"])


class RejectBadInput(unittest.TestCase):
    def assert_rejected(self, text, advisory_id="mfsa2026-200"):
        self.assertIsNone(watch.parse_advisory(advisory_id, text))

    def test_empty(self):
        self.assert_rejected("")

    def test_html_page(self):
        self.assert_rejected("<html><body><script>alert(1)</script></body></html>")

    def test_binary_junk(self):
        self.assert_rejected("\x00\x01\xff" * 100)

    def test_oversized(self):
        self.assert_rejected(VALID.format(title="x") + "#" * (watch.MAX_BYTES + 1))

    def test_unknown_impact(self):
        self.assert_rejected(VALID.format(title="x").replace("impact: high", "impact: meltdown"))

    def test_bad_date(self):
        self.assert_rejected(VALID.format(title="x").replace("November 03, 2026", "<b>soon</b>"))

    def test_missing_title(self):
        self.assert_rejected(VALID.format(title=""))

    def test_missing_advisories(self):
        self.assert_rejected(VALID.format(title="x").replace("advisories:", "other:"))

    def test_bad_id(self):
        self.assert_rejected(VALID.format(title="x"), "../../etc/passwd")

    def test_title_is_reduced_to_plain_text(self):
        hostile = '<script>alert(1)</script>[click](http://evil.example) @someone `x`'
        advisory = watch.parse_advisory("mfsa2026-200", VALID.format(title=hostile))
        for bad in "<>[]@`":
            self.assertNotIn(bad, advisory["title"])


class Versions(unittest.TestCase):
    def test_newer(self):
        self.assertTrue(watch.is_newer("159.0.2", "159.0.1"))
        self.assertTrue(watch.is_newer("160", "159.0.1"))

    def test_not_newer(self):
        self.assertFalse(watch.is_newer("159.0.1", "159.0.1"))
        self.assertFalse(watch.is_newer("159", "159.0.1"))
        self.assertFalse(watch.is_newer("158.0.2", "159.0.1"))

    def test_compared_as_numbers(self):
        self.assertTrue(watch.is_newer("1000", "999.9.9"))

    def test_release_tags(self):
        self.assertEqual(watch.release_tag("159.0.1"), "FIREFOX_159_0_1_RELEASE")
        self.assertEqual(watch.release_tag("160"), "FIREFOX_160_0_RELEASE")


def fake_fetch(files):
    return lambda year, advisory_id: files.get(advisory_id)


class FindNewAdvisories(unittest.TestCase):
    def find(self, files, baseline="mfsa2026-122", pinned="159.0.1", this_year=2026):
        return watch.new_advisories(fake_fetch(files), baseline, pinned, this_year)[0]

    def test_nothing_new(self):
        self.assertEqual(self.find({}), [])

    def test_fix_in_newer_firefox_alerts(self):
        text = fixture("mfsa2026-123")
        found = self.find({"mfsa2026-123": text}, pinned="159.0")
        self.assertEqual([a["id"] for a in found], ["mfsa2026-123"])

    def test_fix_already_in_this_build_does_not_alert(self):
        self.assertEqual(self.find({"mfsa2026-123": fixture("mfsa2026-123")}), [])

    def test_esr_and_thunderbird_do_not_alert(self):
        files = {
            "mfsa2026-123": fixture("mfsa2026-120"),
            "mfsa2026-124": fixture("mfsa2026-121"),
        }
        self.assertEqual(self.find(files), [])

    def test_malformed_advisory_does_not_alert_or_stop_the_walk(self):
        files = {
            "mfsa2026-123": "<html>not an advisory</html>",
            "mfsa2026-124": VALID.format(title="Real one"),
        }
        self.assertEqual([a["id"] for a in self.find(files)], ["mfsa2026-124"])

    def test_single_gap_in_numbering_is_skipped(self):
        files = {"mfsa2026-124": VALID.format(title="After a gap")}
        self.assertEqual([a["id"] for a in self.find(files)], ["mfsa2026-124"])

    def test_walk_moves_into_the_new_year(self):
        files = {"mfsa2027-1": VALID.format(title="New year")}
        found = self.find(files, this_year=2027)
        self.assertEqual([a["id"] for a in found], ["mfsa2027-1"])

    def test_progress_moves_past_every_advisory_seen(self):
        files = {"mfsa2026-123": fixture("mfsa2026-120")}
        _, last_seen = watch.new_advisories(
            fake_fetch(files), "mfsa2026-122", "159.0.1", 2026
        )
        self.assertEqual(last_seen, "mfsa2026-123")

    def test_progress_stays_put_when_nothing_is_new(self):
        _, last_seen = watch.new_advisories(
            fake_fetch({}), "mfsa2026-122", "159.0.1", 2026
        )
        self.assertEqual(last_seen, "mfsa2026-122")

    def test_walk_stops_at_the_current_year(self):
        calls = []

        def fetch(year, advisory_id):
            calls.append(advisory_id)

        watch.new_advisories(fetch, "mfsa2026-122", "159.0.1", 2026)
        self.assertEqual(calls, ["mfsa2026-123", "mfsa2026-124"])


class AlertText(unittest.TestCase):
    def advisory(self, **changes):
        return {**parsed("mfsa2026-123"), **changes}

    def test_body_has_the_details_and_next_step(self):
        body = watch.alert_body(self.advisory())
        self.assertIn("mfsa2026-123", body)
        self.assertIn("scripts/rebase FIREFOX_159_0_1_RELEASE", body)

    def test_title_contains_the_id_for_deduplication(self):
        self.assertIn("mfsa2026-123", watch.alert_title(self.advisory()))

    def test_exploited_is_flagged_first(self):
        title = watch.alert_title(self.advisory(exploited=True))
        self.assertTrue(title.startswith("EXPLOITED"))

    def test_test_alert_is_labelled(self):
        self.assertTrue(watch.alert_title(watch.test_advisory()).startswith("TEST"))

    def test_no_deadline_is_promised(self):
        body = watch.alert_body(self.advisory()).lower()
        for word in ("deadline", "48", "hours"):
            self.assertNotIn(word, body)


if __name__ == "__main__":
    unittest.main()
