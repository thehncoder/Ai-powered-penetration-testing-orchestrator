"""
CVSS v3.1 Calculator Engine according to FIRST Specification.
Calculates Base Scores, generates standardized vector strings, and validates metrics.
"""

import math
from typing import Dict, Any, Tuple
from core.schemas import CVSSMetrics, SeverityLevel


class CVSSEngine:
    """Calculates CVSS 3.1 Base Scores from metrics or vector strings."""

    # Weights according to FIRST CVSS v3.1 specification
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    
    # PR depends on Scope
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    
    IMPACT_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

    @staticmethod
    def _roundup(val: float) -> float:
        """FIRST CVSS v3.1 round-up function."""
        round_10 = round(val * 100000)
        if (round_10 % 10000) == 0:
            return round_10 / 100000.0
        else:
            return (math.floor(round_10 / 10000) + 1) / 10.0

    @classmethod
    def calculate_base_score(
        cls,
        av: str = "N",   # Network, Adjacent, Local, Physical
        ac: str = "L",   # Low, High
        pr: str = "N",   # None, Low, High
        ui: str = "N",   # None, Required
        s: str = "U",    # Unchanged, Changed
        c: str = "H",    # None, Low, High
        i: str = "H",    # None, Low, High
        a: str = "H"     # None, Low, High
    ) -> Tuple[float, SeverityLevel, str]:
        """Returns (base_score, SeverityLevel, vector_string)"""
        av = av.upper()
        ac = ac.upper()
        pr = pr.upper()
        ui = ui.upper()
        s = s.upper()
        c = c.upper()
        i = i.upper()
        a = a.upper()

        vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        # Exploitability sub-score
        pr_weight = cls.PR_WEIGHTS_CHANGED[pr] if s == "C" else cls.PR_WEIGHTS_UNCHANGED[pr]
        exploitability = 8.22 * cls.AV_WEIGHTS[av] * cls.AC_WEIGHTS[ac] * pr_weight * cls.UI_WEIGHTS[ui]

        # Impact sub-score (ISS)
        iss = 1.0 - ((1.0 - cls.IMPACT_WEIGHTS[c]) * (1.0 - cls.IMPACT_WEIGHTS[i]) * (1.0 - cls.IMPACT_WEIGHTS[a]))

        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0:
            base_score = 0.0
        else:
            if s == "U":
                raw_score = min(impact + exploitability, 10.0)
            else:
                raw_score = min(1.08 * (impact + exploitability), 10.0)
            base_score = cls._roundup(raw_score)

        base_score = round(min(max(base_score, 0.0), 10.0), 1)

        # Determine Severity
        if base_score == 0.0:
            severity = SeverityLevel.INFORMATIONAL
        elif base_score <= 3.9:
            severity = SeverityLevel.LOW
        elif base_score <= 6.9:
            severity = SeverityLevel.MEDIUM
        elif base_score <= 8.9:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.CRITICAL

        return base_score, severity, vector_string

    @classmethod
    def create_metrics(
        cls,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "H"
    ) -> CVSSMetrics:
        score, severity, vector = cls.calculate_base_score(av, ac, pr, ui, s, c, i, a)
        
        av_map = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
        ac_map = {"L": "LOW", "H": "HIGH"}
        pr_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
        ui_map = {"N": "NONE", "R": "REQUIRED"}
        s_map = {"U": "UNCHANGED", "C": "CHANGED"}
        imp_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}

        return CVSSMetrics(
            version="3.1",
            vector_string=vector,
            base_score=score,
            severity=severity,
            attack_vector=av_map.get(av, "NETWORK"),
            attack_complexity=ac_map.get(ac, "LOW"),
            privileges_required=pr_map.get(pr, "NONE"),
            user_interaction=ui_map.get(ui, "NONE"),
            scope=s_map.get(s, "UNCHANGED"),
            confidentiality=imp_map.get(c, "HIGH"),
            integrity=imp_map.get(i, "HIGH"),
            availability=imp_map.get(a, "HIGH"),
        )

    @classmethod
    def get_template_metrics(cls, vuln_type: str) -> CVSSMetrics:
        """Returns standard CVSS 3.1 metrics for standard vulnerability classes."""
        v = vuln_type.lower()
        if "sql" in v or "sqli" in v:
            # Critical: Network, Low complexity, No privs, No UI, Scope Unchanged, High C, High I, High A -> 9.8
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
        elif "ssrf" in v:
            # High: Network, Low, No privs, No UI, Scope Changed, High C, Low I, None A -> 8.6
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="L", a="N")
        elif "rce" in v or "command_injection" in v:
            # Critical: Network, Low, No privs, No UI, Scope Changed, High C, High I, High A -> 10.0
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H")
        elif "idor" in v or "broken_access" in v:
            # High: Network, Low, Low privs, No UI, Scope Unchanged, High C, High I, None A -> 8.1
            return cls.create_metrics(av="N", ac="L", pr="L", ui="N", s="U", c="H", i="H", a="N")
        elif "xss" in v:
            # Medium/High: Network, Low, None, Required, Scope Changed, Low C, Low I, None A -> 6.1
            return cls.create_metrics(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")
        elif "cors" in v:
            # Medium: Network, Low, None, Required, Scope Unchanged, High C, None I, None A -> 6.5
            return cls.create_metrics(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="N", a="N")
        elif "jwt" in v or "auth" in v:
            # High: Network, Low, None, None, Scope Unchanged, High C, High I, None A -> 9.1
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N")
        elif "misconfig" in v or "header" in v:
            # Low: Network, Low, None, None, Scope Unchanged, Low C, None I, None A -> 5.3
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N")
        else:
            return cls.create_metrics(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="L", a="N")
