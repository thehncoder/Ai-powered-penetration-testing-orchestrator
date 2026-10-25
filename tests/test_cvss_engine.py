"""
Unit tests for CVSS v3.1 Engine.
"""

import pytest
from core.cvss_engine import CVSSEngine
from core.schemas import SeverityLevel


def test_cvss_critical_sqli():
    score, sev, vector = CVSSEngine.calculate_base_score(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert score == 9.8
    assert sev == SeverityLevel.CRITICAL
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_xss_medium():
    score, sev, vector = CVSSEngine.calculate_base_score(
        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
    )
    assert score == 6.1
    assert sev == SeverityLevel.MEDIUM
    assert "UI:R" in vector
    assert "S:C" in vector


def test_cvss_template_helper():
    metrics = CVSSEngine.get_template_metrics("sqli")
    assert metrics.base_score == 9.8
    assert metrics.severity == SeverityLevel.CRITICAL
