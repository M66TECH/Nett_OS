# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du registre explicite de nettoyeurs (règle 6 d'architecture)."""

from __future__ import annotations

import datetime as dt

import pytest

from nettos.cleaners.base import BaseCleaner, CleanerStatus
from nettos.cleaners.registry import (
    MAX_RULE_AGE_DAYS,
    CleanerRegistry,
    _all_cleaner_types,
    default_registry,
)
from nettos.cleaners.rules import CleanerRule, CleanTarget, Platform, RiskLevel
from nettos.cleaners.rules_linux import LINUX_CLEANERS
from nettos.cleaners.rules_windows import WINDOWS_CLEANERS


def _fake_cleaner(rule: CleanerRule) -> type[BaseCleaner]:
    class _Fake(BaseCleaner):
        RULE = rule

        @property
        def rule(self) -> CleanerRule:
            return rule

        def roots(self):  # type: ignore[no-untyped-def]
            return []

        def simulate(self):  # type: ignore[no-untyped-def]
            raise NotImplementedError

    return _Fake


def _rule(**overrides: object) -> CleanerRule:
    params: dict[str, object] = {
        "identifier": "fake.sample.rule",
        "title": "Fake",
        "description": "d",
        "version": "1",
        "platforms": frozenset({Platform.LINUX}),
        "risk": RiskLevel.LOW,
        "targets": (CleanTarget("*.tmp", "tmp"),),
        "valid_from": dt.date(2026, 1, 1),
        "reviewed_on": dt.date(2026, 1, 1),
    }
    params.update(overrides)
    return CleanerRule(**params)  # type: ignore[arg-type]


class TestRegistryContent:
    def test_shipped_rules_are_all_registered(self) -> None:
        registry = CleanerRegistry(platform=Platform.LINUX)

        assert len(registry) == len(LINUX_CLEANERS) + len(WINDOWS_CLEANERS)

    def test_all_cleaner_types_are_explicit(self) -> None:
        """La liste est littérale : aucune découverte dynamique sur disque."""
        assert _all_cleaner_types() == (*LINUX_CLEANERS, *WINDOWS_CLEANERS)

    def test_every_shipped_rule_has_a_rule_object(self) -> None:
        registry = CleanerRegistry()

        assert all(entry.rule is not None for entry in registry)

    def test_identifiers_are_unique(self) -> None:
        registry = CleanerRegistry()

        identifiers = [entry.identifier for entry in registry]
        assert len(identifiers) == len(set(identifiers))

    def test_entries_are_sorted_by_identifier(self) -> None:
        registry = CleanerRegistry()

        identifiers = [entry.identifier or "" for entry in registry]
        assert identifiers == sorted(identifiers)


class TestPlatformFiltering:
    def test_linux_rules_not_applicable_on_windows(self) -> None:
        registry = CleanerRegistry(platform=Platform.WINDOWS)

        linux_entries = [e for e in registry if (e.identifier or "").startswith("linux.")]
        assert linux_entries
        assert all(e.status is CleanerStatus.NOT_APPLICABLE for e in linux_entries)

    def test_windows_rules_active_on_windows(self) -> None:
        registry = CleanerRegistry(platform=Platform.WINDOWS)

        active = registry.active_entries()
        assert active
        assert all((e.identifier or "").startswith("windows.") for e in active)

    def test_linux_rules_active_on_linux(self) -> None:
        registry = CleanerRegistry(platform=Platform.LINUX)

        active = {e.identifier for e in registry.active_entries()}
        assert active == {cleaner.RULE.identifier for cleaner in LINUX_CLEANERS}


class TestStatuses:
    def test_stale_rule_is_not_active(self) -> None:
        old = dt.date.today() - dt.timedelta(days=MAX_RULE_AGE_DAYS + 10)
        registry = CleanerRegistry(
            platform=Platform.LINUX,
            today=dt.date.today(),
            disabled=frozenset(),
        )
        rule = _rule(reviewed_on=old, valid_from=old)

        status, reason = registry._evaluate(rule)

        assert status is CleanerStatus.STALE
        assert "revue" in reason

    def test_disabled_rule_is_not_active(self) -> None:
        registry = CleanerRegistry(platform=Platform.LINUX)
        rule = _rule()

        status, reason = registry._evaluate(rule)
        assert status is CleanerStatus.ACTIVE

        registry._disabled = frozenset({rule.identifier})
        status, reason = registry._evaluate(rule)
        assert status is CleanerStatus.DISABLED
        assert "désactivée" in reason

    def test_default_registry_uses_current_platform(self) -> None:
        registry = default_registry()

        assert registry.platform in {Platform.LINUX, Platform.WINDOWS}


class TestInstantiation:
    def test_cannot_instantiate_inactive_rule(self) -> None:
        registry = CleanerRegistry(platform=Platform.WINDOWS)

        with pytest.raises(PermissionError, match="pas actif"):
            registry.instantiate("linux.user.cache")

    def test_unknown_rule_raises_key_error(self) -> None:
        registry = CleanerRegistry()

        with pytest.raises(KeyError, match="inconnu"):
            registry.instantiate("does.not.exist")

    def test_active_rule_instantiates(self) -> None:
        registry = CleanerRegistry(platform=Platform.LINUX)

        cleaner = registry.instantiate("linux.user.thumbnails")
        assert cleaner.identifier == "linux.user.thumbnails"

    def test_get_returns_rule_without_instantiating(self) -> None:
        registry = CleanerRegistry()

        rule = registry.get("linux.user.cache")
        assert rule is not None
        assert rule.risk is RiskLevel.MODERATE

    def test_get_unknown_returns_none(self) -> None:
        assert CleanerRegistry().get("nope.nope") is None


class TestSafetyInvariants:
    def test_execute_is_blocked(self) -> None:
        """Aucune suppression possible avant la phase 4."""
        registry = CleanerRegistry(platform=Platform.LINUX)
        cleaner = registry.instantiate("linux.user.thumbnails")

        with pytest.raises(NotImplementedError, match="phase 4"):
            cleaner.execute()

    def test_no_shipped_rule_requires_admin(self) -> None:
        """Aucune règle livrée n'exige d'élévation de privilèges."""
        registry = CleanerRegistry()

        assert all(entry.rule is not None and not entry.rule.requires_admin for entry in registry)

    def test_no_shipped_rule_is_high_risk(self) -> None:
        """Les règles livrées restent faibles ou modérées."""
        registry = CleanerRegistry()

        for entry in registry:
            assert entry.rule is not None
            assert entry.rule.risk <= RiskLevel.MODERATE, entry.identifier

    def test_no_shipped_target_is_absolute(self) -> None:
        registry = CleanerRegistry()

        for entry in registry:
            assert entry.rule is not None
            for target in entry.rule.targets:
                normalized = target.pattern.replace("\\", "/")
                assert not normalized.startswith("/")
                assert ".." not in normalized.split("/")

    def test_rules_do_not_target_system_areas(self) -> None:
        """Aucune règle livrée ne vise /etc, C:\\Windows ou le registre."""
        forbidden_markers = (
            "/etc",
            "/var/lib",
            "/boot",
            "C:/Windows",
            "System32",
            "WinSxS",
            "regedit",
        )
        registry = CleanerRegistry()

        for entry in registry:
            assert entry.rule is not None
            patterns = " ".join(t.pattern for t in entry.rule.targets)
            for marker in forbidden_markers:
                assert marker.lower() not in patterns.lower(), entry.identifier
