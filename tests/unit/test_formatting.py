# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de mise en forme des tailles (unités décimales et binaires)."""

from __future__ import annotations

import pytest

from nettos.core.formatting import format_bytes


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0 o"),
        (1, "1 o"),
        (999, "999 o"),
        (1024, "1.0 Kio"),
        (1536, "1.5 Kio"),
        (1024**2, "1.0 Mio"),
        (1024**3, "1.0 Gio"),
        (1024**4, "1.0 Tio"),
    ],
)
def test_binary_units(value: int, expected: str) -> None:
    assert format_bytes(value, binary=True) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1000, "1.0 ko"),
        (1500, "1.5 ko"),
        (1000**2, "1.0 Mo"),
        (1000**3, "1.0 Go"),
    ],
)
def test_decimal_units(value: int, expected: str) -> None:
    assert format_bytes(value, binary=False) == expected


def test_negative_is_clamped_to_zero() -> None:
    assert format_bytes(-42) == "0 o"


def test_precision_is_configurable() -> None:
    assert format_bytes(1536, precision=2) == "1.50 Kio"
