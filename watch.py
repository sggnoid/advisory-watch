#!/usr/bin/env python3
"""Alert the maintainer about new Firefox security advisories.

Reads Mozilla's advisories directly, one numbered file at a time. Advisory text
is untrusted, so only validated fields are kept.

  python3 watch.py            print what's new
  python3 watch.py --notify   also send a phone push, file issues, save progress
  python3 watch.py --test-alert
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

STATE_FILE = Path(__file__).resolve().parent / "watch.json"
ADVISORY_URL = (
    "https://raw.githubusercontent.com/mozilla/foundation-security-advisories"
    "/master/announce/{year}/{id}.yml"
)
PAGE_URL = "https://www.mozilla.org/en-US/security/advisories/{id}/"
LABEL = "security-upstream"
MAX_BYTES = 1_000_000
MAX_GAP = 2
IMPACTS = ("critical", "high", "moderate", "low")

ID_FORMAT = re.compile(r"^mfsa(\d{4})-(\d{1,4})$")
FIREFOX_LINE = re.compile(r"^- Firefox (\d{1,4}(?:\.\d{1,4}){0,2})[ \t]*$", re.M)
CVE_KEY = re.compile(r"^  (?:CVE-\d{4}-\d{4,}|MFSA-[A-Za-z0-9-]+):[ \t]*$", re.M)
DATE_FORMAT = re.compile(r"^[A-Z][a-z]{2,8} \d{1,2}, \d{4}$")
EXPLOITED = re.compile(
    r"exploit\w*\s+in[\s-]the[\s-]wild|in[\s-]the[\s-]wild\s+exploit", re.I
)


def top_level(text, key):
    match = re.search(rf"^{key}:[ \t]*(.*?)[ \t]*$", text, re.M)
    return match.group(1) if match else None


def clean_text(value):
    without_tags = re.sub(r"<[^>]*>", "", value)
    return re.sub(r"[^A-Za-z0-9 .,:;()'/_-]", "", without_tags).strip()[:200]


def parse_advisory(advisory_id, text):
    """Return validated fields, or None if the text isn't a well-formed advisory."""
    if len(text) > MAX_BYTES or not ID_FORMAT.match(advisory_id):
        return None
    announced = top_level(text, "announced")
    impact = top_level(text, "impact")
    title = top_level(text, "title")
    if not announced or not DATE_FORMAT.match(announced):
        return None
    if impact not in IMPACTS or not title or top_level(text, "fixed_in") is None:
        return None
    if top_level(text, "advisories") is None:
        return None
    versions = FIREFOX_LINE.findall(text)
    return {
        "id": advisory_id,
        "announced": announced,
        "impact": impact,
        "title": clean_text(title),
        "firefox_version": versions[0] if versions else None,
        "cve_count": len(CVE_KEY.findall(text)),
        "exploited": bool(EXPLOITED.search(text)),
    }


def version_key(version):
    parts = [int(part) for part in version.split(".")]
    return parts + [0] * (3 - len(parts))


def is_newer(version, pinned):
    return version_key(version) > version_key(pinned)


def walk_advisories(fetch, baseline, this_year):
    """Yield (id, text) for every advisory published after the baseline."""
    match = ID_FORMAT.match(baseline)
    if not match:
        raise ValueError(f"bad advisory id: {baseline}")
    year, number = int(match.group(1)), int(match.group(2))
    misses = 0
    while True:
        number += 1
        advisory_id = f"mfsa{year}-{number}"
        text = fetch(year, advisory_id)
        if text is not None:
            misses = 0
            yield advisory_id, text
            continue
        misses += 1
        if misses < MAX_GAP:
            continue
        if year >= this_year:
            return
        year, number, misses = year + 1, 0, 0


def new_advisories(fetch, baseline, pinned, this_year):
    """Return (Firefox advisories newer than pinned, last advisory id seen)."""
    found = []
    last_seen = baseline
    for advisory_id, text in walk_advisories(fetch, baseline, this_year):
        last_seen = advisory_id
        advisory = parse_advisory(advisory_id, text)
        if advisory is None:
            print(f"warning: ignoring malformed {advisory_id}", file=sys.stderr)
        elif advisory["firefox_version"] and is_newer(
            advisory["firefox_version"], pinned
        ):
            found.append(advisory)
    return found, last_seen


def fetch_advisory(year, advisory_id):
    url = ADVISORY_URL.format(year=year, id=advisory_id)
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            return response.read(MAX_BYTES + 1).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def release_tag(version):
    parts = version.split(".")
    if len(parts) == 1:
        parts.append("0")
    return f"FIREFOX_{'_'.join(parts)}_RELEASE"


def alert_title(advisory):
    prefix = "EXPLOITED: " if advisory["exploited"] else ""
    if advisory.get("test"):
        prefix = "TEST: "
    return (
        f"{prefix}Firefox {advisory['firefox_version']} security fix "
        f"({advisory['impact']}, {advisory['id']})"
    )


def alert_body(advisory):
    lines = [
        advisory["title"],
        "",
        f"- Announced: {advisory['announced']}",
        f"- Highest impact: {advisory['impact']}",
        f"- Vulnerabilities: {advisory['cve_count']}",
        f"- Exploited in the wild: {'possibly, check the advisory' if advisory['exploited'] else 'not reported'}",
        f"- Advisory: {PAGE_URL.format(id=advisory['id'])}",
        "",
        f"To update: `scripts/rebase {release_tag(advisory['firefox_version'])}`",
    ]
    return "\n".join(lines)


def already_filed(advisory):
    output = subprocess.check_output(
        ["gh", "issue", "list", "--label", LABEL, "--state", "all"]
        + ["--search", f"{advisory['id']} in:title", "--json", "number"],
        text=True,
    )
    return bool(json.loads(output))


def file_issue(advisory):
    subprocess.check_call(
        ["gh", "issue", "create", "--label", LABEL]
        + ["--title", alert_title(advisory), "--body", alert_body(advisory)]
    )


def send_push(advisory):
    url = os.environ.get("NTFY_URL")
    if not url:
        print("warning: NTFY_URL isn't set, so no phone push", file=sys.stderr)
        return
    urgent = advisory["exploited"] or advisory["impact"] == "critical"
    request = urllib.request.Request(
        url,
        data=alert_body(advisory).encode(),
        headers={
            "Title": alert_title(advisory),
            "Priority": "5" if urgent else "4",
            "Click": PAGE_URL.format(id=advisory["id"]),
        },
    )
    urllib.request.urlopen(request, timeout=20).close()


def notify(advisory):
    if already_filed(advisory):
        return
    # Push first: a failed issue only repeats the push next run, but a failed
    # push after a filed issue would never be retried.
    send_push(advisory)
    file_issue(advisory)


def test_advisory():
    return {
        "id": f"mfsa-test-{datetime.datetime.now(datetime.timezone.utc):%Y%m%d%H%M%S}",
        "announced": "This is a test",
        "impact": "low",
        "title": "Test alert. Nothing needs doing.",
        "firefox_version": "0.0.0",
        "cve_count": 0,
        "exploited": False,
        "test": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--test-alert", action="store_true")
    args = parser.parse_args()

    if args.test_alert:
        notify(test_advisory())
        return

    state = json.loads(STATE_FILE.read_text())
    found, last_seen = new_advisories(
        fetch_advisory,
        state["last_advisory"],
        state["version"],
        datetime.date.today().year,
    )
    print(json.dumps(found, indent=2))
    if args.notify:
        for advisory in found:
            notify(advisory)
        state["last_advisory"] = last_seen
        STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")


if __name__ == "__main__":
    main()
