"""
Print what the agent actually writes, so a human can judge it.

The evals in tests/eval answer "did the contract hold". They cannot answer "is this
any good", because no mechanical check can tell a sharp board line from a limp one.
This runs the agent over the same fixtures and prints the output in full.

Run from backend/ with the venv active:

    python scripts/review_agent_output.py                  # read it
    python scripts/review_agent_output.py > review.md      # keep it to diff later

Needs ANTHROPIC_API_KEY. Does NOT need Supabase: the fixtures stand in for the
database, so this works before the stack is up. Costs a few cents per run.
"""

import asyncio
import os
import pathlib
import sys

_BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND))
# app.config reads .env relative to the working directory, so run from backend/
# whatever directory the user actually invoked this from. Shell redirects are
# resolved before Python starts, so this does not move the output file.
os.chdir(_BACKEND)

import anthropic

from app.config import settings
from app.tls import configure_trust

configure_trust()
from app.models.enums import RiskDomain
from app.services import card_generator, clustering
from app.services.card_validation import validate_card

# One source of truth for the fixtures: the evals define them, this reuses them.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests" / "eval"))
from test_agent_quality import (
    CARD_CLUSTER,
    SAME_THREAT,
    UNRELATED_PRODUCTS,
    _CaptureDB,
    _grounding_chunks,
)

RULE = "=" * 78


def show_card(card: dict, chunks: list, label: str) -> None:
    errors = validate_card(card, SAME_THREAT, chunks)
    print(f"\n{RULE}\n{label}\n{RULE}")
    print(f"rewrites needed : {card['metadata']['validation_attempts'] - 1}")
    print(f"contract        : {'clean' if not errors else 'FAILED: ' + '; '.join(errors)}")
    print(f"model           : {card['metadata']['model']}")
    print(f"\nBOARD ONE-LINER (non-technical director reads this)\n  {card['simple_headline']}")
    print(f"\nHEADLINE\n  {card['signal_headline']}")
    print(f"\nBOARD TALKING POINT\n  {card['board_talking_point']}")
    print(f"\nREGULATORY EXPOSURE\n  {card['compliance_gap']}")
    print(f"\nQUESTION FOR THE TEAM\n  {card['contextual_question']}")
    print(f"\nTEAMS  {', '.join(card['affected_teams'])}")
    print("\nEVIDENCE")
    for item in card["evidence_stack"]:
        print(f"  [{item['source']}] {item['title']}")
        print(f"      {item['point']}")
        print(f"      link: {item.get('url') or '(none)'}")
    print("\nJudge for yourself: is the one-liner something a CFO would repeat, and does")
    print("the regulatory paragraph say anything the evidence above actually supports?")


async def main() -> None:
    if not settings.anthropic_api_key:
        sys.exit("ANTHROPIC_API_KEY not set")

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key, max_retries=8)
    chunks = _grounding_chunks()

    print(RULE)
    print("AGENT OUTPUT REVIEW")
    print(RULE)
    print("Two clustering decisions, then two cards. The contract check is mechanical;")
    print("the wording is not, which is why it is printed in full.")

    # Clustering: the judgement no validator can check.
    print(f"\n{RULE}\nCLUSTERING 1 of 2: one threat, three sources. Should make ONE cluster.\n{RULE}")
    db = _CaptureDB()
    await clustering._cluster_batch(db, client, RiskDomain.VULNERABILITY_PATCH, SAME_THREAT, 1, 1)
    print(f"clusters made: {len(db.rows)}  {'as expected' if len(db.rows) == 1 else 'UNEXPECTED'}")
    for row in db.rows:
        print(f"  risk_vector : {row['risk_vector']}")
        print(f"  summary     : {row['cluster_summary']}")
        print(f"  score       : {row['score']}  from {row['signal_count']} signals / {row['source_count']} sources")

    print(f"\n{RULE}\nCLUSTERING 2 of 2: three unrelated products. Should NOT merge them.\n{RULE}")
    db = _CaptureDB()
    await clustering._cluster_batch(db, client, RiskDomain.VULNERABILITY_PATCH, UNRELATED_PRODUCTS, 1, 1)
    merged = [r for r in db.rows if len(r["signal_ids"]) > 1]
    print(f"clusters made: {len(db.rows)}, merged: {len(merged)}  {'as expected' if not merged else 'UNEXPECTED MERGE'}")
    for row in db.rows:
        print(f"  {len(row['signal_ids'])} signal(s): {row['risk_vector']}")

    # Card with regulation text retrieved.
    db = _CaptureDB()
    db.signals = SAME_THREAT
    original = card_generator.search_regulations
    card_generator.search_regulations = lambda d, q, match_count=5: chunks
    try:
        await card_generator._generate_one(db, client, CARD_CLUSTER)
        show_card(db.rows[0], chunks, "CARD 1 of 2: WITH regulation text retrieved (the normal path)")
        print("\nSource figures the agent was given, to check its citations against:")
        for c in chunks:
            print(f"  [{c['regulation']} {c['article_ref']}] {c['title']}")
    finally:
        card_generator.search_regulations = original

    # Card with nothing retrieved: must stay general, no article numbers or fines.
    db = _CaptureDB()
    db.signals = SAME_THREAT
    card_generator.search_regulations = lambda d, q, match_count=5: []
    try:
        await card_generator._generate_one(db, client, CARD_CLUSTER)
        show_card(db.rows[0], [], "CARD 2 of 2: NO regulation text (must not cite articles or fines)")
    finally:
        card_generator.search_regulations = original

    await client.close()


asyncio.run(main())
