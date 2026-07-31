"""
Evidence links must point at the signal the agent was given, never at a URL it wrote.

The agent has been observed inventing plausible landing pages
(https://www.cisa.gov/known-exploited-vulnerabilities-catalog) in place of the
actual advisory URL. Those links look right in review and go to the wrong page.
"""

from app.services.card_generator import resolve_evidence_urls

SIGNALS = [
    {"title": "Cisco IOS XE Web UI Privilege Escalation Vulnerability", "url": "https://kev.example/real-1"},
    {"title": "CVE-2023-20198", "url": "https://nvd.example/real-2"},
]


def test_database_url_overwrites_a_url_the_agent_invented():
    stack = [{"title": "CVE-2023-20198", "url": "https://www.nvd.nist.gov"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_database_url_fills_in_when_the_agent_omits_one():
    stack = [{"title": "CVE-2023-20198"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_url_is_blanked_when_the_title_matches_no_signal():
    stack = [{"title": "Something the agent made up", "url": "https://plausible.example"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == ""


def test_other_evidence_fields_are_left_alone():
    stack = [{"title": "CVE-2023-20198", "source": "NVD", "point": "Actively exploited."}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["point"] == "Actively exploited."


# The prompt renders each signal as "- [SOURCE] title (severity: X)" followed by the
# summary, so the agent copies that decoration into the title field. Real runs produced
# "[NVD] CVE-2026-58023 (severity: critical)" and even the summary on the next line.

def test_matches_a_title_carrying_the_prompt_source_prefix():
    stack = [{"title": "[NVD] CVE-2023-20198"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_matches_a_title_carrying_the_prompt_severity_suffix():
    stack = [{"title": "CVE-2023-20198 (severity: critical)"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_matches_a_title_carrying_both_prefix_and_suffix():
    stack = [{"title": "[NVD] CVE-2023-20198 (severity: critical)"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_matches_when_the_agent_appended_the_summary_on_later_lines():
    stack = [{"title": "[NVD] CVE-2023-20198 (severity: critical)\n  Some summary text.\n\n  More."}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == "https://nvd.example/real-2"


def test_still_rejects_a_title_the_agent_actually_invented():
    stack = [{"title": "[NVD] CVE-9999-00000 (severity: critical)"}]
    resolved = resolve_evidence_urls(stack, SIGNALS)
    assert resolved[0]["url"] == ""
