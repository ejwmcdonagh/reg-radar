"""
Card contract tests - the offline half of the agent quality loop.

Every card the agent writes must satisfy the contract encoded in the
write_risk_card tool schema. These tests pin that contract so a prompt change
that quietly breaks it fails here instead of on a board slide.
"""

from app.services.card_validation import blocking_errors, normalise_card, validate_card

# Signals the agent was given. evidence_stack entries must trace back to these.
SIGNALS = [
    {"source": "cisa_kev", "title": "Cisco IOS XE Web UI Privilege Escalation Vulnerability", "url": "https://kev.example/1"},
    {"source": "nvd", "title": "CVE-2023-20198", "url": "https://nvd.example/2"},
]

# Retrieved regulation text. Only figures appearing here may be cited.
REG_CHUNKS = [
    {
        "regulation": "nis2",
        "article_ref": "Article 32 and 33",
        "title": "Supervisory measures and sanctions - fines",
        "content": (
            "For essential entities, NIS2 provides for administrative fines of at least "
            "10,000,000 EUR or at least 2% of the total worldwide annual turnover. For "
            "important entities, administrative fines of at least 7,000,000 EUR or at "
            "least 1.4% of total worldwide annual turnover."
        ),
    },
]


def valid_card(**overrides):
    """A card that passes every check. Tests override one field at a time."""
    card = {
        "signal_headline": "Attackers creating admin accounts on unpatched Cisco routers",
        "simple_headline": "Attackers can take full control of equipment that runs our network.",
        "evidence_stack": [
            {"source": "CISA KEV", "title": "Cisco IOS XE Web UI Privilege Escalation Vulnerability", "point": "Confirmed exploited."},
        ],
        "contextual_question": "Do we run this equipment anywhere on the public internet?",
        "compliance_gap": "Exposes the organisation to fines of at least 10,000,000 EUR under NIS2 Article 32 and 33.",
        "board_talking_point": (
            "Attackers can take over the equipment that runs our network. "
            "That risks fines of at least 10,000,000 EUR. "
            "The board needs to approve emergency patching this week."
        ),
        "affected_teams": ["Network", "SOC"],
    }
    card.update(overrides)
    return card


def test_accepts_a_card_meeting_every_rule():
    errors = validate_card(valid_card(), SIGNALS, REG_CHUNKS)
    assert errors == []


def test_rejects_signal_headline_longer_than_fifteen_words():
    card = valid_card(signal_headline=" ".join(["word"] * 16))
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("signal_headline" in e for e in errors)


def test_rejects_simple_headline_longer_than_fifteen_words():
    card = valid_card(simple_headline=" ".join(["word"] * 16))
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("simple_headline" in e for e in errors)


def test_rejects_jargon_in_simple_headline():
    card = valid_card(simple_headline="An authentication bypass lets attackers in.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("authentication bypass" in e for e in errors)


def test_rejects_cve_number_in_board_talking_point():
    card = valid_card(board_talking_point="CVE-2023-20198 affects us. We must patch it. The board must approve.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("CVE" in e for e in errors)


def test_accepts_a_five_sentence_board_talking_point():
    # Five short sentences still reads as board copy. Failing them closed cost real
    # cards in production for no editorial gain.
    card = valid_card(board_talking_point=(
        "Attackers can take over the equipment that runs our network. "
        "They can reach customer systems from there. "
        "That risks fines of at least 10,000,000 EUR. "
        "We have not yet confirmed which devices are exposed. "
        "The board needs to approve emergency patching this week."
    ))
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert errors == []


def test_rejects_board_talking_point_shorter_than_three_sentences():
    card = valid_card(board_talking_point="Attackers can take over our network. Approve patching.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("board_talking_point" in e and "sentence" in e for e in errors)


def test_rejects_affected_team_outside_the_allowed_set():
    card = valid_card(affected_teams=["Network", "Marketing"])
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("Marketing" in e for e in errors)


def test_rejects_more_than_three_affected_teams():
    card = valid_card(affected_teams=["Network", "SOC", "IAM", "GRC"])
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("affected_teams" in e for e in errors)


def test_accepts_evidence_title_decorated_by_the_prompt_format():
    # The prompt shows "- [SOURCE] title (severity: X)", so the agent copies it whole.
    card = valid_card(evidence_stack=[{
        "source": "CISA KEV",
        "title": "[CISA KEV] Cisco IOS XE Web UI Privilege Escalation Vulnerability (severity: critical)",
        "point": "Confirmed exploited.",
    }])
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert errors == []


def test_rejects_evidence_title_not_traceable_to_a_supplied_signal():
    card = valid_card(evidence_stack=[{"source": "CISA KEV", "title": "A headline the agent invented", "point": "x"}])
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("not traceable" in e for e in errors)


def test_rejects_empty_evidence_stack():
    card = valid_card(evidence_stack=[])
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("evidence_stack" in e for e in errors)


def test_rejects_fine_figure_absent_from_retrieved_regulation_text():
    # The real failure seen in production: source says 7,000,000 EUR / 1.4%,
    # the agent wrote a 10-14 million range that appears in no chunk.
    card = valid_card(compliance_gap="Fines run to 14,000,000 EUR under NIS2 Article 32 and 33.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("14000000" in e.replace(",", "") for e in errors)


def test_rejects_percentage_absent_from_retrieved_regulation_text():
    card = valid_card(compliance_gap="Fines reach 2.8% of turnover under NIS2 Article 32 and 33.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("2.8%" in e for e in errors)


def test_accepts_figure_written_with_a_scale_word():
    # "10 million" and "10,000,000" are the same figure - do not flag it.
    card = valid_card(compliance_gap="Fines of at least 10 million EUR apply under NIS2 Article 32 and 33.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert errors == []


def test_rejects_article_reference_absent_from_retrieved_regulation_text():
    card = valid_card(compliance_gap="This breaches UK GDPR Article 99 on infrastructure resilience.")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("Article 99" in e for e in errors)


def test_rejects_any_article_reference_when_no_regulation_text_was_retrieved():
    # Fail closed: with RAG unavailable the agent has nothing to cite from.
    card = valid_card(compliance_gap="This breaches UK GDPR Article 32 on security of processing.")
    errors = validate_card(card, SIGNALS, [])
    assert any("Article 32" in e for e in errors)


def test_rejects_any_fine_figure_when_no_regulation_text_was_retrieved():
    card = valid_card(
        compliance_gap="Exposes us to serious regulatory sanction.",
        board_talking_point=(
            "Attackers can take over our network. "
            "This risks fines of 20,000,000 EUR. "
            "The board must approve emergency patching."
        ),
    )
    errors = validate_card(card, SIGNALS, [])
    assert any("20000000" in e.replace(",", "") for e in errors)


def test_accepts_unquantified_compliance_gap_when_no_regulation_text_was_retrieved():
    card = valid_card(
        compliance_gap="Exposes the organisation to regulatory sanction under NIS2 and UK GDPR.",
        board_talking_point=(
            "Attackers can take over the equipment that runs our network. "
            "That puts customer service and data at risk. "
            "The board needs to approve emergency patching this week."
        ),
    )
    errors = validate_card(card, SIGNALS, [])
    assert errors == []


def test_rejects_em_dash_in_card_copy():
    # Project style bans em dashes in UI copy, and cards are UI copy.
    card = valid_card(contextual_question="Do we run this kit externally — anywhere at all?")
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("em dash" in e for e in errors)


def test_rejects_missing_required_field():
    card = valid_card()
    del card["contextual_question"]
    errors = validate_card(card, SIGNALS, REG_CHUNKS)
    assert any("contextual_question" in e for e in errors)


# Blocking vs advisory. A fabricated fine must never reach a board, so it blocks the
# card. Prose that runs long is a style miss and binning the whole card over it throws
# away real intelligence, so it is recorded and shipped.

def test_an_overlong_board_talking_point_does_not_block_the_card():
    card = valid_card(board_talking_point=" ".join(f"Sentence number {i}." for i in range(8)))
    assert blocking_errors(card, SIGNALS, REG_CHUNKS) == []


def test_an_overlong_board_talking_point_is_still_reported():
    card = valid_card(board_talking_point=" ".join(f"Sentence number {i}." for i in range(8)))
    assert any("sentences" in e for e in validate_card(card, SIGNALS, REG_CHUNKS))


def test_an_ungrounded_fine_figure_blocks_the_card():
    card = valid_card(compliance_gap="Fines reach 14,000,000 EUR under NIS2 Article 32 and 33.")
    assert any("14000000" in e.replace(",", "") for e in blocking_errors(card, SIGNALS, REG_CHUNKS))


def test_jargon_in_board_copy_blocks_the_card():
    card = valid_card(simple_headline="An authentication bypass lets attackers in.")
    assert any("authentication bypass" in e for e in blocking_errors(card, SIGNALS, REG_CHUNKS))


def test_untraceable_evidence_blocks_the_card():
    card = valid_card(evidence_stack=[{"source": "X", "title": "Invented headline", "point": "x"}])
    assert any("not traceable" in e for e in blocking_errors(card, SIGNALS, REG_CHUNKS))


def test_an_overlong_headline_does_not_block_the_card():
    card = valid_card(simple_headline=" ".join(["word"] * 20))
    assert blocking_errors(card, SIGNALS, REG_CHUNKS) == []


# Normalisation - deterministic fixes applied before validation, so the agent is
# not asked to burn a retry on something a string replace can settle.

def test_normalise_replaces_em_dash_in_a_top_level_field():
    card = normalise_card(valid_card(contextual_question="Do we run this — anywhere?"))
    assert card["contextual_question"] == "Do we run this - anywhere?"


def test_normalise_keeps_words_apart_when_the_em_dash_had_no_spaces():
    # The agent writes "companies—triggering fines". A bare swap gives
    # "companies-triggering", which reads as a hyphenated compound word.
    card = normalise_card(valid_card(contextual_question="Fines hit companies—triggering audits?"))
    assert card["contextual_question"] == "Fines hit companies - triggering audits?"


def test_normalise_replaces_em_dash_inside_evidence_points():
    card = valid_card(evidence_stack=[{"source": "CISA KEV", "title": "t", "point": "Widespread — act now."}])
    assert normalise_card(card)["evidence_stack"][0]["point"] == "Widespread - act now."


def test_normalise_leaves_compliant_copy_untouched():
    card = valid_card()
    assert normalise_card(card) == card
