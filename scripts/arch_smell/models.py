#!/usr/bin/env python3
"""Data models for architecture smell detection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class InfraSignal:
    """A detected infrastructure usage within a function."""

    category: str  # db, http, filesystem, env, logging, time, random, subprocess
    call: str  # The actual call/access
    line: int


@dataclass(slots=True, frozen=True)
class DecisionSignal:
    """A detected decision/logic construct within a function."""

    kind: str  # if, match, raise, assert, ternary, comprehension, any/all, try
    line: int
