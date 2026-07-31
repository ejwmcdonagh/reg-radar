"""
Risk intelligence card generator for Pulse.

Takes pending signal clusters above the score threshold and generates a
5-layer risk card for each using Claude.

The 5 layers:
  1. Signal headline     - what is happening right now, present tense
  2. Evidence stack      - the signals that triggered this card, source attributed
  3. Contextual question - "is this true in your organisation?"
  4. Regulatory exposure - which regulations make this commercially consequential
  5. Board talking point - plain English risk summary the CISO can take to the board

The framing is risk-first. Regulations are supporting evidence for why the risk
matters commercially, not the primary lens. A card about an actively exploited RCE
should open with the threat, not the compliance gap.
"""

import logging
from typing import Any

import anthropic

from app.config import settings
from app.db.client import get_db
from app.services.card_validation import (
    blocking_errors,
    normalise_card,
    normalise_title,
    validate_card,
)
from app.services.embeddings import search_regulations

logger = logging.getLogger(__name__)

# How many times the agent may rewrite one card before the cluster is failed.
# Board-facing copy fails closed: a card citing a fine figure that appears in no
# retrieved regulation is worse than no card at all.
_VALIDATION_ATTEMPTS = 3


class CardValidationError(Exception):
    """The agent could not produce a card meeting the contract within the retry budget."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors

_CARD_TOOL: dict[str, Any] = {
    "name": "write_risk_card",
    "description": "Write a 5-layer risk intelligence card for a CISO audience. Risk first, regulatory context second.",
    "input_schema": {
        "type": "object",
        "properties": {
            "signal_headline": {
                "type": "string",
                "description": "Present-tense threat headline, max 15 words. Lead with what attackers are doing or what is broken. Factual, no jargon.",
            },
            "evidence_stack": {
                "type": "array",
                "description": "The signals that triggered this card, one entry per signal.",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string"},
                        "title": {
                            "type": "string",
                            "description": (
                                "Copy the value of the signal's 'title:' field exactly, and nothing else. "
                                "Do not include the source, the severity, or the summary, and do not reword it. "
                                "This is how the card is matched back to the stored link."
                            ),
                        },
                        "url": {"type": "string"},
                        "point": {"type": "string", "description": "One sentence on what this signal adds to the risk picture"},
                    },
                    "required": ["source", "title", "point"],
                },
            },
            "contextual_question": {
                "type": "string",
                "description": "One direct question for the CISO's team. Focus on exposure: do we have this, are we affected, have we verified? Answerable with yes/no or a specific metric.",
            },
            "compliance_gap": {
                "type": "string",
                "description": (
                    "2-3 sentences on which regulations make this risk commercially consequential. "
                    "Frame as: exposes the org to [consequence] under [framework]. "
                    "Where regulatory context is provided below, cite specific articles and fine "
                    "thresholds from that context. Do not invent article numbers or fine figures."
                ),
            },
            "simple_headline": {
                "type": "string",
                "description": (
                    "HARD LIMIT 15 words. Count the words before you return, and aim for 12 - "
                    "the agent overshoots this cap more than any other field. "
                    "One sentence for a non-technical board director or CFO. "
                    "Explain the real-world risk in plain English with zero technical terms. "
                    "No CVE numbers, no product names, no vulnerability class names (no 'authentication bypass', "
                    "'SQL injection', 'RCE', 'buffer overflow', 'XSS', 'privilege escalation', etc.). "
                    "Write what could go wrong for the business, not what the flaw is. "
                    "Example: 'Attackers can log into critical systems without a password and take full control.'"
                ),
            },
            "board_talking_point": {
                "type": "string",
                "description": (
                    "3-4 sentences for non-technical board directors. "
                    "(1) What is happening in plain English - no CVE numbers, no technical class names "
                    "(say 'attackers can log in without a password' not 'authentication bypass'); "
                    "(2) specific business consequence - real fine figure, insurance denial, or revenue impact; "
                    "(3) one action the board needs to approve. "
                    "Active voice. Short sentences. Write like a CFO, not an engineer."
                ),
            },
            "affected_teams": {
                "type": "array",
                "description": "1-3 teams from: IAM, SOC, AppSec, Cloud/Infra, Network, Endpoint, GRC, Data/Privacy. Only include teams with a clear connection to the threat.",
                "items": {"type": "string"},
            },
        },
        "required": [
            "signal_headline",
            "simple_headline",
            "evidence_stack",
            "contextual_question",
            "compliance_gap",
            "board_talking_point",
            "affected_teams",
        ],
    },
}

_SYSTEM_PROMPT = """You are a threat intelligence analyst writing risk briefings for CISOs at large organisations.

Take clusters of live threat signals and write clear risk cards. Risk is always the primary lens - lead with the threat, not compliance. Regulations appear only where they make the commercial consequence more concrete.

Board talking point: write for non-technical directors. Plain English, no CVE numbers, no acronyms. State a specific business consequence (real fine figure, insurance impact, or revenue risk). End with one clear ask. Three to four short sentences. Active voice.

All other layers: write for the CISO - technically literate, commercially aware. Reference real frameworks where relevant: NIS2, UK GDPR, DORA, FCA SYSC 13, ISO 27001, NCSC CAF.

Do not fabricate CVE numbers, vendor names, or breach figures beyond what the signals contain."""


def resolve_evidence_urls(
    evidence_stack: list[dict[str, Any]],
    signals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Point every evidence link at the stored signal URL, never the agent's.

    The agent writes plausible landing pages from memory when it cannot recall the
    real link, and those survive review because they look correct. The stored URL
    is the one that was actually fetched, so it always wins.
    """
    url_by_title = {normalise_title(s["title"]): s.get("url", "") for s in signals}
    return [
        {**item, "url": url_by_title.get(normalise_title(item.get("title", "")), "")}
        for item in evidence_stack
    ]


async def generate_cards(cluster_ids: list[str] | None = None) -> int:
    """
    Generate provocation cards for pending clusters above the score threshold.

    If cluster_ids is provided, generate cards for only those clusters
    (used by the manual API trigger for targeted re-generation).
    Returns the number of cards written.
    """
    if not settings.anthropic_api_key:
        logger.warning("ANTHROPIC_API_KEY not set - skipping card generation")
        return 0

    db = get_db()

    _MAX_ATTEMPTS = 3

    if cluster_ids:
        # Manual regeneration path (used after prompt tuning). Reset state first
        # so the cluster goes through the normal flow: delete any existing card,
        # reset the cluster status and attempt counter. Without this, an existing
        # card_generated cluster would produce a duplicate card with the same
        # cluster_id (the provocation_cards table has no unique constraint).
        db.table("provocation_cards").delete().in_("cluster_id", cluster_ids).execute()
        db.table("signal_clusters").update({
            "status": "pending",
            "card_generation_attempts": 0,
        }).in_("id", cluster_ids).execute()

        result = (
            db.table("signal_clusters")
            .select("*")
            .in_("id", cluster_ids)
            .execute()
        )
    else:
        # Exclude clusters that have already failed too many times - they won't
        # suddenly start working without a code change or data fix
        result = (
            db.table("signal_clusters")
            .select("*")
            .eq("status", "pending")
            .lt("card_generation_attempts", _MAX_ATTEMPTS)
            .gte("score", settings.card_score_threshold)
            .order("score", desc=True)
            .execute()
        )

    clusters: list[dict[str, Any]] = result.data or []

    if not clusters:
        logger.info("Card generation: no qualifying clusters found")
        return 0

    logger.info("Generating cards for %d clusters", len(clusters))
    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    written = 0

    for cluster in clusters:
        try:
            card_written = await _generate_one(db, client, cluster)
            if card_written:
                written += 1
        except Exception as exc:
            logger.exception("Card generation failed for cluster %s", cluster["id"])
            attempts = (cluster.get("card_generation_attempts") or 0) + 1
            new_status = "failed" if attempts >= _MAX_ATTEMPTS else "pending"
            update: dict[str, Any] = {
                "card_generation_attempts": attempts,
                "status": new_status,
            }
            # Keep the reason on the row so a rejected cluster can be triaged
            # without digging through logs from a run that happened overnight.
            if isinstance(exc, CardValidationError):
                update["metadata"] = {
                    **(cluster.get("metadata") or {}),
                    "validation_errors": exc.errors,
                }
            db.table("signal_clusters").update(update).eq("id", cluster["id"]).execute()
            if new_status == "failed":
                logger.warning(
                    "Cluster %s marked failed after %d attempts - will not be retried",
                    cluster["id"], attempts,
                )
            continue

    logger.info("Card generation complete: %d cards written", written)
    return written


async def _generate_one(db: Any, client: anthropic.Anthropic, cluster: dict[str, Any]) -> bool:
    """Generate and persist a single provocation card. Returns True if written."""
    cluster_id: str = cluster["id"]
    signal_ids: list[str] = cluster.get("signal_ids", [])

    if not signal_ids:
        return False

    # Fetch the full signals for this cluster
    signals_result = (
        db.table("signals")
        .select("source, title, summary, severity, url, signal_type, risk_domains")
        .in_("id", signal_ids)
        .execute()
    )
    signals: list[dict[str, Any]] = signals_result.data or []

    if not signals:
        return False

    # Retrieve relevant regulation chunks to ground the compliance_gap in real text
    rag_query = f"{cluster['cluster_summary']} {cluster.get('risk_vector', '')}"
    reg_chunks = search_regulations(db, rag_query, match_count=5)

    # Build a compact signal list for the prompt
    signal_descriptions = [
        {
            "source": s["source"].upper().replace("_", " "),
            "title": s["title"],
            "summary": (s.get("summary") or "")[:250],
            "severity": s.get("severity"),
            "url": s.get("url") or "",
            "signal_type": s.get("signal_type"),
        }
        for s in signals
    ]

    # With nothing retrieved the agent falls back on remembered regulation text and
    # writes article numbers and fine figures it cannot support. Saying so explicitly
    # is what stops it: validation would otherwise reject the card three times and
    # fail the cluster outright.
    reg_context = (
        "\n\nNo regulatory context was retrieved for this cluster. Name frameworks in "
        "general terms only (NIS2, UK GDPR, DORA, FCA SYSC 13, ISO 27001, NCSC CAF). "
        "Do NOT cite article numbers, control references, or fine figures anywhere in "
        "the card - there is no source text here to support them."
    )
    if reg_chunks:
        chunk_lines = []
        for chunk in reg_chunks:
            label = f"[{chunk['regulation'].upper().replace('_', ' ')} - {chunk['article_ref']}] {chunk['title']}"
            chunk_lines.append(f"{label}\n{chunk['content']}")
        reg_context = (
            "\n\nRelevant regulatory context - use this to write the compliance_gap field:\n\n"
            + "\n\n".join(chunk_lines)
        )

    user_message = (
        f"Generate a provocation card for the following signal cluster.\n\n"
        f"Cluster summary: {cluster['cluster_summary']}\n"
        f"Risk vector: {cluster['risk_vector']}\n"
        f"Primary domain: {cluster['risk_domain']}\n"
        f"All domains: {', '.join(cluster.get('metadata', {}).get('all_domains', [cluster['risk_domain']]))}\n"
        f"Signal count: {cluster['signal_count']}\n"
        f"Source count: {cluster['source_count']}\n"
        f"Highest severity: {cluster.get('severity_max') or 'unknown'}\n\n"
        f"Signals:\n"
        # Each field on its own labelled line. When the title was rendered inline as
        # "- [SOURCE] title (severity: X)" the agent copied the whole decorated line
        # into evidence_stack.title, which then matched no stored signal.
        + "\n\n".join(
            f"- title: {s['title']}\n  source: {s['source']}"
            + (f"\n  severity: {s['severity']}" if s.get("severity") else "")
            + (f"\n  summary: {s['summary']}" if s.get("summary") else "")
            for s in signal_descriptions
        )
        + reg_context
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
    card_input: dict[str, Any] | None = None
    errors: list[str] = []
    attempt = 0

    for attempt in range(1, _VALIDATION_ATTEMPTS + 1):
        response = await client.messages.create(
            # To switch to Opus, replace the model string and uncomment the thinking line.
            # Thinking is not supported on Haiku - only uncomment it when using Opus.
            model="claude-haiku-4-5-20251001",
            # model="claude-opus-4-7",
            max_tokens=1500,
            system=_SYSTEM_PROMPT,
            tools=[_CARD_TOOL],
            tool_choice={"type": "tool", "name": "write_risk_card"},
            messages=messages,
        )

        tool_block = next((b for b in response.content if b.type == "tool_use"), None)
        if not tool_block:
            logger.warning("No tool_use block in card generation response for cluster %s", cluster_id)
            return False

        candidate = normalise_card(tool_block.input)
        errors = validate_card(candidate, signal_descriptions, reg_chunks)
        if not errors:
            card_input = candidate
            break

        # Out of rewrites: ship it if nothing left is a factual problem. Losing a
        # sound card because its board summary ran long is worse than the long summary.
        if attempt == _VALIDATION_ATTEMPTS:
            blocking = blocking_errors(candidate, signal_descriptions, reg_chunks)
            if not blocking:
                logger.info(
                    "Cluster %s accepted with %d advisory issue(s): %s",
                    cluster_id, len(errors), "; ".join(errors),
                )
                card_input = candidate
                break
            errors = blocking

        logger.warning(
            "Card for cluster %s failed validation (attempt %d/%d): %s",
            cluster_id, attempt, _VALIDATION_ATTEMPTS, "; ".join(errors),
        )

        # Forced tool_choice makes the model's turn a tool_use block, so the
        # correction has to come back as a tool_result or the API rejects the turn.
        messages = messages + [
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_block.id,
                        "is_error": True,
                        "content": (
                            "The card was rejected. Fix every point below and call the tool again.\n"
                            + "\n".join(f"- {e}" for e in errors)
                        ),
                    }
                ],
            },
        ]

    if card_input is None:
        raise CardValidationError(errors)

    # Build the evidence stack - use the model's structured output but enrich
    # with the actual signal URLs from the DB which are more reliable
    evidence_stack = resolve_evidence_urls(card_input.get("evidence_stack", []), signal_descriptions)

    card_row = {
        "cluster_id": cluster_id,
        "signal_headline": card_input["signal_headline"],
        "simple_headline": card_input.get("simple_headline"),
        "evidence_stack": evidence_stack,
        "compliance_gap": card_input["compliance_gap"],
        "contextual_question": card_input["contextual_question"],
        "board_talking_point": card_input["board_talking_point"],
        "affected_teams": list(dict.fromkeys(card_input.get("affected_teams", []))),
        "risk_domain": cluster["risk_domain"],
        "score": cluster["score"],
        "metadata": {
            "model": response.model,
            # Rewrites needed before the card passed. Persisted because a rising
            # average here is the earliest signal that a prompt change regressed.
            "validation_attempts": attempt,
            # Style issues the agent would not fix. Empty on a clean card.
            "validation_warnings": validate_card(card_input, signal_descriptions, reg_chunks),
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            "cluster_summary": cluster["cluster_summary"],
            "signal_count": cluster["signal_count"],
            "source_count": cluster["source_count"],
            "severity_max": cluster.get("severity_max"),
            "all_domains": cluster.get("metadata", {}).get("all_domains", [cluster["risk_domain"]]),
        },
    }

    db.table("provocation_cards").insert(card_row).execute()

    # Mark the cluster so it isn't re-processed on the next run
    db.table("signal_clusters").update({"status": "card_generated"}).eq("id", cluster_id).execute()

    logger.info(
        "Card written: cluster=%s domain=%s score=%.1f",
        cluster_id,
        cluster["risk_domain"],
        cluster["score"],
    )
    return True
