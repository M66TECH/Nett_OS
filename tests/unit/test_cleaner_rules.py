# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du modèle déclaratif des règles de nettoyage."""

from __future__ import annotations

import datetime as dt

import pytest

from nettos.cleaners.rules import (
    CleanerRule,
    CleanTarget,
    Platform,
    RiskLevel,
    _is_valid_identifier,
)


def _rule(**overrides: object) -> CleanerRule:
    params: dict[str, object] = {
        "identifier": "test.sample.rule",
        "title": "Titre",
        "description": "Description",
        "version": "1",
        "platforms": frozenset({Platform.LINUX}),
        "risk": RiskLevel.LOW,
        "targets": (CleanTarget(pattern="*.tmp", description="temporaires"),),
        "valid_from": dt.date(2026, 1, 1),
        "reviewed_on": dt.date(2026, 1, 1),
    }
    params.update(overrides)
    return CleanerRule(**params)  # type: ignore[arg-type]


class TestRiskLevel:
    def test_is_ordered(self) -> None:
        assert RiskLevel.LOW < RiskLevel.MODERATE < RiskLevel.HIGH < RiskLevel.FORBIDDEN

    def test_label_is_stable(self) -> None:
        assert RiskLevel.LOW.label == "low"
        assert RiskLevel.FORBIDDEN.label == "forbidden"

    def test_high_and_above_need_extra_confirmation(self) -> None:
        assert not RiskLevel.LOW.requires_extra_confirmation
        assert not RiskLevel.MODERATE.requires_extra_confirmation
        assert RiskLevel.HIGH.requires_extra_confirmation

    @pytest.mark.parametrize("text", ["low", "LOW", " Low "])
    def test_parse_is_case_insensitive(self, text: str) -> None:
        assert RiskLevel.parse(text) is RiskLevel.LOW

    def test_parse_rejects_unknown(self) -> None:
        with pytest.raises(ValueError, match="inconnu"):
            RiskLevel.parse("catastrophic")


class TestPlatform:
    def test_parse(self) -> None:
        assert Platform.parse("linux") is Platform.LINUX
        assert Platform.parse("Windows") is Platform.WINDOWS

    def test_parse_rejects_unknown(self) -> None:
        with pytest.raises(ValueError, match="inconnue"):
            Platform.parse("macos")


class TestCleanTarget:
    def test_accepts_relative_pattern(self) -> None:
        assert CleanTarget(pattern="cache/**/*.log", description="journaux")

    @pytest.mark.parametrize(
        "pattern",
        ["/etc/passwd", "\\Windows\\System32", "C:\\Windows", "../outside", ""],
    )
    def test_rejects_absolute_or_escaping_pattern(self, pattern: str) -> None:
        with pytest.raises(ValueError):
            CleanTarget(pattern=pattern, description="interdit")

    def test_rejects_negative_age(self) -> None:
        with pytest.raises(ValueError):
            CleanTarget(pattern="*.tmp", description="x", max_age_days=-1)


class TestCleanerRule:
    def test_valid_rule_is_accepted(self) -> None:
        rule = _rule()

        assert rule.identifier == "test.sample.rule"
        assert rule.applies_to(Platform.LINUX)
        assert not rule.applies_to(Platform.WINDOWS)

    def test_risky_flags(self) -> None:
        rule = _rule(risk=RiskLevel.HIGH)

        assert rule.risk.requires_extra_confirmation

    def test_forbidden_rule_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="FORBIDDEN"):
            _rule(risk=RiskLevel.FORBIDDEN)

    def test_requires_at_least_one_target(self) -> None:
        with pytest.raises(ValueError, match="au moins une cible"):
            _rule(targets=())

    def test_requires_at_least_one_platform(self) -> None:
        with pytest.raises(ValueError, match="au moins une plateforme"):
            _rule(platforms=frozenset())

    def test_reviewed_before_validity_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="revue"):
            _rule(
                valid_from=dt.date(2026, 6, 1),
                reviewed_on=dt.date(2026, 5, 1),
            )

    def test_future_validity_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="pas encore valide"):
            _rule(valid_from=dt.date(2999, 1, 1), reviewed_on=dt.date(2999, 1, 1))

    def test_valid_for_days(self) -> None:
        start = dt.date.today() - dt.timedelta(days=10)
        rule = _rule(valid_from=start, reviewed_on=start)

        assert rule.valid_for_days == 10

    def test_no_date_means_not_stale(self) -> None:
        rule = _rule(valid_from=None, reviewed_on=None)

        assert rule.valid_for_days is None
        assert not rule.is_stale

    def test_old_rule_is_stale(self) -> None:
        old = dt.date.today() - dt.timedelta(days=1000)
        rule = _rule(valid_from=old, reviewed_on=old)

        assert rule.is_stale

    def test_rule_is_immutable(self) -> None:
        rule = _rule()

        with pytest.raises(AttributeError):
            rule.identifier = "autre"  # type: ignore[misc]


class TestIdentifierValidation:
    @pytest.mark.parametrize(
        "identifier",
        ["linux.user.cache", "windows.user.temp", "a.b", "test-1.sample_2.rule"],
    )
    def test_valid_identifiers(self, identifier: str) -> None:
        assert _is_valid_identifier(identifier)

    @pytest.mark.parametrize(
        "identifier",
        ["", "Linux.User", "linux..user", ".linux", "linux.", "1linux.user", "linux user"],
    )
    def test_invalid_identifiers(self, identifier: str) -> None:
        assert not _is_valid_identifier(identifier)
