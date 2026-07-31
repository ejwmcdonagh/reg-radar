"""
Live evals. These call the real model, so they cost money and are excluded from
the normal test run. Run them deliberately:

    pytest -m eval

What they are for: the unit tests pin the code, these pin the agent's judgement.
A prompt edit that reads better but clusters worse passes every unit test and
fails here. Each case is a claim about behaviour that a human already agreed with,
so a failure means either the agent regressed or the claim needs re-arguing.

Two things are measured:
  1. Clustering decisions - does the agent group what a human would group?
  2. Card contract compliance, and how much rewriting it took to get there.

Cards are retried until they comply, so a finished card never looks bad. The cost
of compliance is the thing that degrades quietly, which is why attempts are asserted
on as well as the final card.
"""

import json
from pathlib import Path

import anthropic
import pytest

from app.config import settings
from app.models.enums import RiskDomain
from app.services import card_generator, clustering
from app.services.card_validation import _article_refs, validate_card

_CHUNKS_PATH = Path(__file__).resolve().parents[2] / "data" / "regulation_chunks.json"

pytestmark = [
    pytest.mark.eval,
    # Read through settings, not os.getenv: the key normally lives in backend/.env,
    # which pydantic loads into settings and never puts in the environment. Checking
    # the environment made every eval skip silently on a machine that was correctly
    # configured, which looks identical to a passing run.
    pytest.mark.skipif(
        not settings.anthropic_api_key,
        reason="live eval needs ANTHROPIC_API_KEY in backend/.env or the environment",
    ),
]


def signal(sid, source, title, summary, severity="high", stype="vulnerability", published="2026-05-20T09:00:00Z"):
    # url is set so the evidence-link path is actually exercised: the agent invents
    # plausible source URLs, and resolve_evidence_urls has to overwrite them.
    return {
        "id": sid, "source": source, "title": title, "summary": summary,
        "severity": severity, "cvss_score": None, "risk_domains": ["vulnerability_patch"],
        "published_at": published, "signal_type": stype, "tags": [],
        "url": f"https://signals.example/{sid}",
    }


# One vulnerability reported by three sources. A patch manager should get one card.
SAME_THREAT = [
    signal("a1", "cisa_kev", "Cisco IOS XE Web UI Privilege Escalation Vulnerability",
           "Cisco IOS XE Web UI allows a remote unauthenticated attacker to create an account with privilege level 15 access.",
           "critical", "advisory"),
    signal("a2", "nvd", "CVE-2023-20198",
           "Active exploitation of a vulnerability in the Web User Interface of Cisco IOS XE Software exposed to the internet.",
           "critical"),
    signal("a3", "cisa_advisories", "Cisco Releases Security Advisory for IOS XE Software Web UI",
           "CISA urges organisations to disable the HTTP server feature on internet-facing Cisco IOS XE systems.",
           "high", "advisory"),
]

# Three unrelated products that happen to share a vulnerability class. Grouping
# these produces a card no one can act on, which is the failure mode the prompt
# calls out by name.
UNRELATED_PRODUCTS = [
    signal("b1", "nvd", "CVE-2026-1111 GitLab remote code execution",
           "A flaw in GitLab CE allows an authenticated user to execute arbitrary code on the server."),
    signal("b2", "nvd", "CVE-2026-2222 VMware vCenter remote code execution",
           "A flaw in VMware vCenter Server allows an attacker on the management network to execute arbitrary code."),
    signal("b3", "nvd", "CVE-2026-3333 Apache Struts remote code execution",
           "A flaw in Apache Struts allows a remote attacker to execute arbitrary code via a crafted request."),
]


class _CaptureDB:
    """Stub DB that records inserted rows instead of writing to Postgres."""

    def __init__(self):
        self.rows = []
        self.signals = []

    def table(self, name):
        return self

    def select(self, *a, **k):
        return self

    def in_(self, *a, **k):
        return self

    def eq(self, *a, **k):
        return self

    def update(self, *a, **k):
        return self

    def insert(self, row):
        self.rows.append(row)
        return self

    def rpc(self, *a, **k):
        # No pgvector here, so RAG retrieval comes back empty and the agent is
        # held to the fail-closed rule: no article numbers without grounding.
        return type("Rpc", (), {"execute": lambda _self: type("R", (), {"data": []})()})()

    def execute(self):
        return type("R", (), {"data": self.signals})()


def _grounding_chunks():
    """The five chunks a vector search would return for a router patching threat."""
    chunks = json.loads(_CHUNKS_PATH.read_text())
    want = [
        ("nis2", "Article 18"), ("uk_gdpr", "Article 32"), ("nis2", "Article 23"),
        ("dora", "Article 5"), ("nis2", "Article 32 and 33"),
    ]
    return [c for reg, ref in want for c in chunks if c["regulation"] == reg and c["article_ref"].startswith(ref)]


CARD_CLUSTER = {
    "id": "eval-card", "signal_ids": ["a1", "a2", "a3"],
    "cluster_summary": "Attackers are creating admin accounts on internet-facing Cisco IOS-XE devices.",
    "risk_vector": "Unauthenticated admin account creation via Cisco IOS-XE web UI",
    "risk_domain": "vulnerability_patch", "signal_count": 3, "source_count": 3,
    "severity_max": "critical", "score": 78.0,
    "metadata": {"all_domains": ["vulnerability_patch"]},
}


@pytest.fixture
async def client():
    # Closed explicitly: an unclosed AsyncAnthropic outlives its event loop and the
    # next test in the run dies with "Event loop is closed".
    c = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key, max_retries=8)
    yield c
    await c.close()


@pytest.mark.asyncio
async def test_groups_one_vulnerability_reported_by_three_sources(client):
    db = _CaptureDB()
    await clustering._cluster_batch(db, client, RiskDomain.VULNERABILITY_PATCH, SAME_THREAT, 1, 1)
    assert len(db.rows) == 1, f"expected one cluster, got {[r['risk_vector'] for r in db.rows]}"


@pytest.mark.asyncio
async def test_does_not_merge_unrelated_products_sharing_a_vulnerability_class(client):
    db = _CaptureDB()
    await clustering._cluster_batch(db, client, RiskDomain.VULNERABILITY_PATCH, UNRELATED_PRODUCTS, 1, 1)
    merged = [r for r in db.rows if len(r["signal_ids"]) > 1]
    assert merged == [], f"unrelated products were merged: {[r['risk_vector'] for r in merged]}"


@pytest.mark.asyncio
async def test_card_for_a_grounded_cluster_meets_the_contract(client):
    db = _CaptureDB()
    db.signals = SAME_THREAT
    cluster = {
        "id": "eval-1", "signal_ids": ["a1", "a2", "a3"],
        "cluster_summary": "Attackers are creating admin accounts on internet-facing Cisco IOS-XE devices.",
        "risk_vector": "Unauthenticated admin account creation via Cisco IOS-XE web UI",
        "risk_domain": "vulnerability_patch", "signal_count": 3, "source_count": 3,
        "severity_max": "critical", "score": 78.0,
        "metadata": {"all_domains": ["vulnerability_patch"]},
    }
    await card_generator._generate_one(db, client, cluster)
    card = db.rows[0]
    assert validate_card(card, SAME_THREAT, []) == []


@pytest.mark.asyncio
async def test_cited_figures_and_articles_trace_to_the_retrieved_regulation_text(client, monkeypatch):
    """
    The case that motivated all of this.

    Given real regulation text saying 10,000,000 EUR / 2% and 7,000,000 EUR / 1.4%,
    the agent was observed writing "10-14 million or 2-2.8%". Both the 14 million and
    the 2.8% were invented. Grounding alone did not stop it.

    Two assertions are needed together. Clean validation alone is satisfiable by
    writing nothing specific at all, so this also checks the agent actually used the
    text it was given.
    """
    chunks = _grounding_chunks()
    assert len(chunks) == 5, "fixture drifted from regulation_chunks.json"
    monkeypatch.setattr(card_generator, "search_regulations", lambda db, q, match_count=5: chunks)

    db = _CaptureDB()
    db.signals = SAME_THREAT
    await card_generator._generate_one(db, client, CARD_CLUSTER)
    card = db.rows[0]

    assert _article_refs(card["compliance_gap"]), "agent cited nothing despite being given regulation text"
    assert validate_card(card, SAME_THREAT, chunks) == []


@pytest.mark.asyncio
async def test_card_needs_at_most_one_rewrite_to_meet_the_contract(client):
    """
    Cheap guard on prompt drift.

    The gate is deliberately loose. Card generation runs at default temperature, so
    a single sample cannot prove a first-pass rate and asserting attempts == 1 would
    flake on a healthy prompt. Needing all three attempts is different: it means the
    agent could not self-correct from explicit feedback, which is a real signal.

    The honest first-pass number comes from production, not from here: average
    metadata.validation_attempts across recent cards. Watch that, not this test.
    """
    db = _CaptureDB()
    db.signals = SAME_THREAT
    cluster = {
        "id": "eval-2", "signal_ids": ["a1", "a2", "a3"],
        "cluster_summary": "Attackers are creating admin accounts on internet-facing Cisco IOS-XE devices.",
        "risk_vector": "Unauthenticated admin account creation via Cisco IOS-XE web UI",
        "risk_domain": "vulnerability_patch", "signal_count": 3, "source_count": 3,
        "severity_max": "critical", "score": 78.0,
        "metadata": {"all_domains": ["vulnerability_patch"]},
    }
    await card_generator._generate_one(db, client, cluster)
    attempts = db.rows[0]["metadata"]["validation_attempts"]
    assert attempts <= 2, f"agent needed {attempts} attempts to satisfy the card contract"
