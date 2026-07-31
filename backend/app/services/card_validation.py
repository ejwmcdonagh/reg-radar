"""
Mechanical checks on a card before it is persisted.

The write_risk_card tool schema states the contract in prose, but a tool schema
only enforces shape, not content: a card that cites an invented fine figure or
writes "privilege escalation" at a board director still validates as a string.
These checks turn the prose contract into something that can fail a run.

Everything here is deterministic. No model call, so it is free to run on every
generation and inside the retry loop.

The citation rules are the important ones. The agent has been observed inventing
fine figures that appear in no retrieved chunk (a source saying 7,000,000 EUR
became a "10-14 million" range), so figures and article references are checked
against the retrieved text rather than trusted.
"""

import re
from typing import Any

REQUIRED_FIELDS = (
    "signal_headline",
    "simple_headline",
    "evidence_stack",
    "contextual_question",
    "compliance_gap",
    "board_talking_point",
    "affected_teams",
)

ALLOWED_TEAMS = {"IAM", "SOC", "AppSec", "Cloud/Infra", "Network", "Endpoint", "GRC", "Data/Privacy"}

# Enumerated in the tool schema as banned from board-facing copy.
JARGON = (
    "authentication bypass",
    "sql injection",
    "rce",
    "buffer overflow",
    "xss",
    "privilege escalation",
    "remote code execution",
    "cross-site scripting",
)

_HEADLINE_MAX_WORDS = 15
# 3 to 5. Four was the original prompt wording, but the agent lands on five often
# enough that failing closed on it discarded otherwise sound cards.
_BOARD_SENTENCE_RANGE = (3, 5)

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_SENTENCE_SPLIT = re.compile(r"[.!?]+")

_NUM = r"\d[\d,]*(?:\.\d+)?"
_RANGE = r"(?:\s*[-–—]\s*(" + _NUM + r"))?"
_SCALE = r"(?:\s*(million|billion|bn|m)\b)?"
# Money written symbol-first (EUR 10 million) or code-last (10,000,000 EUR).
_MONEY_SYMBOL = re.compile(r"[€£$]\s*(" + _NUM + r")" + _RANGE + _SCALE, re.IGNORECASE)
_MONEY_CODE = re.compile(
    r"(" + _NUM + r")" + _RANGE + _SCALE + r"\s*(?:EUR|GBP|USD|euros?|pounds?)\b", re.IGNORECASE
)
_PERCENT = re.compile(r"(" + _NUM + r")" + _RANGE + r"\s*%")
# Article references the agent has been seen citing, in the forms it writes them.
_ARTICLE = re.compile(r"\b(?:Article|Art\.?)\s*(\d+[a-z]?)\b", re.IGNORECASE)
_SYSC = re.compile(r"\bSYSC\s*(\d+[\w.]*)\b", re.IGNORECASE)
_ISO_CONTROL = re.compile(r"\bA\.(\d+(?:\.\d+)+)\b")

_SCALES = {"million": 1_000_000, "m": 1_000_000, "billion": 1_000_000_000, "bn": 1_000_000_000}


# The card prompt renders each signal as "- [SOURCE] title (severity: X)" with the
# summary indented beneath, so the agent copies that decoration into the title field.
# Stripping it here is what lets a correct card match, rather than asking the agent to
# reverse-engineer which substring was the title.
_TITLE_PREFIX = re.compile(r"^\[[^\]]*\]\s*")
_TITLE_SUFFIX = re.compile(r"\s*\(severity:[^)]*\)\s*$", re.IGNORECASE)


def normalise_title(title: str) -> str:
    """Reduce an evidence title to the bare signal title for comparison."""
    first_line = (title or "").split("\n")[0].strip()
    return _TITLE_SUFFIX.sub("", _TITLE_PREFIX.sub("", first_line)).strip()


def _text_fields(card: dict[str, Any]) -> list[tuple[str, str]]:
    """Every human-readable string on the card, as (field_name, text)."""
    out: list[tuple[str, str]] = []
    for key in ("signal_headline", "simple_headline", "contextual_question", "compliance_gap", "board_talking_point"):
        value = card.get(key)
        if isinstance(value, str):
            out.append((key, value))
    for i, item in enumerate(card.get("evidence_stack") or []):
        if isinstance(item, dict) and isinstance(item.get("point"), str):
            out.append((f"evidence_stack[{i}].point", item["point"]))
    return out


def _money_values(text: str) -> set[float]:
    """Absolute money amounts in the text, normalised so 10m and 10,000,000 match."""
    found: set[float] = set()
    for pattern in (_MONEY_SYMBOL, _MONEY_CODE):
        for match in pattern.finditer(text):
            low, high, scale = match.group(1), match.group(2), match.group(3)
            multiplier = _SCALES.get((scale or "").lower(), 1)
            for raw in (low, high):
                if raw:
                    found.add(float(raw.replace(",", "")) * multiplier)
    return found


def _percent_values(text: str) -> set[float]:
    found: set[float] = set()
    for match in _PERCENT.finditer(text):
        for raw in (match.group(1), match.group(2)):
            if raw:
                found.add(float(raw.replace(",", "")))
    return found


def _article_refs(text: str) -> set[str]:
    """Canonical lowercase article references, e.g. 'article 32', 'sysc 13'."""
    refs = {f"article {m.group(1).lower()}" for m in _ARTICLE.finditer(text)}
    refs |= {f"sysc {m.group(1).lower()}" for m in _SYSC.finditer(text)}
    refs |= {f"a.{m.group(1)}" for m in _ISO_CONTROL.finditer(text)}
    return refs


def _citation_errors(card: dict[str, Any], reg_chunks: list[dict[str, Any]]) -> list[str]:
    """
    Check every figure and article reference against the retrieved regulation text.

    With no chunks retrieved the agent has no grounding, so any specific citation
    is unverifiable by definition and the card must stay qualitative.
    """
    errors: list[str] = []
    cited_text = " ".join(
        text for field, text in _text_fields(card) if field in ("compliance_gap", "board_talking_point")
    )

    haystack = " ".join(
        f"{c.get('article_ref', '')} {c.get('title', '')} {c.get('content', '')}" for c in reg_chunks
    ).lower()

    source_money = _money_values(haystack)
    source_percent = _percent_values(haystack)

    for value in sorted(_money_values(cited_text)):
        if value not in source_money:
            errors.append(
                f"compliance_gap/board_talking_point cites the figure {value:,.0f} "
                f"which appears in no retrieved regulation chunk"
            )

    for value in sorted(_percent_values(cited_text)):
        if value not in source_percent:
            errors.append(
                f"compliance_gap/board_talking_point cites {value:g}% which appears "
                f"in no retrieved regulation chunk"
            )

    for ref in sorted(_article_refs(cited_text)):
        if not re.search(rf"\b{re.escape(ref)}\b", haystack):
            errors.append(
                f"compliance_gap/board_talking_point cites {ref.title()} which appears "
                f"in no retrieved regulation chunk"
            )

    return errors


def normalise_card(card: dict[str, Any]) -> dict[str, Any]:
    """
    Apply the fixes that need no judgement, so retries are spent on real problems.

    Only punctuation for now. Anything requiring a rewrite is left for validation
    to reject, because silently rewording board copy would hide a quality failure.
    """
    fixed = dict(card)
    for key in ("signal_headline", "simple_headline", "contextual_question", "compliance_gap", "board_talking_point"):
        if isinstance(fixed.get(key), str):
            fixed[key] = _swap_em_dash(fixed[key])
    if isinstance(fixed.get("evidence_stack"), list):
        fixed["evidence_stack"] = [
            {**item, "point": _swap_em_dash(item["point"])}
            if isinstance(item, dict) and isinstance(item.get("point"), str)
            else item
            for item in fixed["evidence_stack"]
        ]
    return fixed


def _swap_em_dash(text: str) -> str:
    """
    Replace em dashes with a spaced hyphen, the form project style uses.

    Spaces are added because the agent usually writes the dash unspaced. A bare
    character swap turns "companies—triggering fines" into "companies-triggering",
    which reads as one hyphenated word and changes the meaning.
    """
    return re.sub(r"\s*—\s*", " - ", text)


# Advisory rules are style: worth a rewrite, not worth binning a sound card over.
# Everything else blocks, because it is either a factual claim the agent cannot
# support or copy that misleads a board.
ADVISORY = "advise"
BLOCKING = "block"


def validate_card(
    card: dict[str, Any],
    signals: list[dict[str, Any]],
    reg_chunks: list[dict[str, Any]],
) -> list[str]:
    """
    Every contract violation, most useful first. Empty means the card is perfect.

    These strings go back to the model verbatim on retry, so each names the field
    and what is wrong with it.
    """
    return [message for _, message in _checks(card, signals, reg_chunks)]


def blocking_errors(
    card: dict[str, Any],
    signals: list[dict[str, Any]],
    reg_chunks: list[dict[str, Any]],
) -> list[str]:
    """
    Only the violations that must stop a card being saved.

    A fabricated fine figure reaching a board is worse than no card. A board
    summary running to six sentences is not, and discarding that card loses real
    intelligence over prose length.
    """
    return [message for severity, message in _checks(card, signals, reg_chunks) if severity == BLOCKING]


def _checks(
    card: dict[str, Any],
    signals: list[dict[str, Any]],
    reg_chunks: list[dict[str, Any]],
) -> list[tuple[str, str]]:
    """Every check, tagged with whether it blocks persistence."""
    errors: list[tuple[str, str]] = []

    for field in REQUIRED_FIELDS:
        if card.get(field) in (None, "", [], {}):
            errors.append((BLOCKING, f"{field} is missing or empty"))
    if errors:
        return errors

    for field in ("signal_headline", "simple_headline"):
        words = len(card[field].split())
        if words > _HEADLINE_MAX_WORDS:
            errors.append((ADVISORY, f"{field} is {words} words, limit is {_HEADLINE_MAX_WORDS}"))

    for field in ("simple_headline", "board_talking_point"):
        lowered = card[field].lower()
        for term in JARGON:
            if re.search(rf"\b{re.escape(term)}\b", lowered):
                errors.append((BLOCKING, f"{field} contains the banned technical term '{term}'"))
        if _CVE.search(card[field]):
            errors.append((BLOCKING, f"{field} contains a CVE number, which board copy must not use"))

    sentences = [s for s in _SENTENCE_SPLIT.split(card["board_talking_point"]) if s.strip()]
    low, high = _BOARD_SENTENCE_RANGE
    if not low <= len(sentences) <= high:
        errors.append((ADVISORY, f"board_talking_point is {len(sentences)} sentences, needs {low} to {high}"))

    teams = card["affected_teams"]
    if not 1 <= len(teams) <= 3:
        errors.append((ADVISORY, f"affected_teams has {len(teams)} entries, needs 1 to 3"))
    for team in teams:
        if team not in ALLOWED_TEAMS:
            errors.append((BLOCKING, f"affected_teams contains '{team}', which is not one of {sorted(ALLOWED_TEAMS)}"))

    # Evidence must trace to a signal the agent was actually given, otherwise the
    # URL enrichment in card_generator silently ships an entry with no link.
    signal_titles = {normalise_title(s.get("title", "")) for s in signals}
    for i, item in enumerate(card["evidence_stack"]):
        title = item.get("title", "")
        if normalise_title(title) not in signal_titles:
            # Truncated: the agent sometimes copies the whole prompt block, summary included.
            errors.append((
                BLOCKING,
                f"evidence_stack[{i}] title '{title[:80]}' is not traceable to a supplied signal",
            ))

    for field, text in _text_fields(card):
        if "—" in text:
            errors.append((ADVISORY, f"{field} contains an em dash, which project style bans in UI copy"))

    errors.extend((BLOCKING, m) for m in _citation_errors(card, reg_chunks))
    return errors
