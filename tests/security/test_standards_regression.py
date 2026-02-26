"""Standards regression tests for security-control coverage."""

from __future__ import annotations

import csv
from pathlib import Path


def test_minimum_control_coverage_threshold() -> None:
    csv_path = Path("docs/security/standards-mapping.csv")
    rows = list(csv.DictReader(csv_path.read_text().splitlines()))
    assert rows, "standards mapping is empty"

    required = [r for r in rows if r.get("control_id")]
    implemented = [r for r in required if r.get("status", "").strip().lower() == "implemented"]

    coverage = len(implemented) / len(required)
    assert coverage >= 0.80, f"coverage {coverage:.2%} is below 80%"


def test_dashboard_rollout_checklist_exists() -> None:
    checklist = Path("docs/plans/2026-02-26-dashboard-live-feed-rollout-checklist.md")
    assert checklist.exists()
