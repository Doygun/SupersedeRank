from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from src.normalize.cvss40_tables import CVSS_LOOKUP, MAX_COMPOSED, MAX_SEVERITY, REFERENCE_VERSION

BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
THREAT_METRICS = ["E"]
ENV_METRICS = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
SUPPLEMENTAL_METRICS = ["S", "AU", "R", "V", "RE", "U"]
ALL_METRICS = BASE_METRICS + THREAT_METRICS + ENV_METRICS + SUPPLEMENTAL_METRICS

ROUNDING_PRECISION_DECIMALS = 10
DEFAULT_ROUNDING = "decimal"

VALID_VALUES = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
    "E": "XAPU", "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
    "MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN", "MSC": "XHLN", "MSI": "XSHLN", "MSA": "XSHLN",
    "S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH",
    "U": "",
}

LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

class Cvss40ParseError(ValueError):
    pass

def parse_vector_v40(vector: str) -> dict[str, str]:
    text = vector.strip()
    if text.startswith("CVSS:4.0/"):
        text = text[len("CVSS:4.0/"):]
    elif text.startswith("CVSS:"):
        raise Cvss40ParseError(f"CVSS 4.0 vektörü değil: {vector}")
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise Cvss40ParseError(f"Geçersiz bileşen '{part}'")
        key, value = part.split(":", 1)
        if key not in VALID_VALUES:
            raise Cvss40ParseError(f"Bilinmeyen metrik '{key}'")
        if key == "U":
            if value not in ("X", "Clear", "Green", "Amber", "Red"):
                raise Cvss40ParseError(f"Geçersiz U değeri '{value}'")
        elif value not in VALID_VALUES[key]:
            raise Cvss40ParseError(f"Geçersiz değer {key}:{value}")
        if key in metrics:
            raise Cvss40ParseError(f"Yinelenen metrik '{key}'")
        metrics[key] = value
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        raise Cvss40ParseError(f"Eksik temel metrik(ler): {missing}")
    for m in THREAT_METRICS + ENV_METRICS + SUPPLEMENTAL_METRICS:
        metrics.setdefault(m, "X")
    return metrics

def _m(sel: dict[str, str], metric: str) -> str:
    value = sel[metric]
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = sel.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value

def macro_vector(sel: dict[str, str]) -> str:
    av, pr, ui = _m(sel, "AV"), _m(sel, "PR"), _m(sel, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if (_m(sel, "AC") == "L" and _m(sel, "AT") == "N") else 1
    vc, vi, va = _m(sel, "VC"), _m(sel, "VI"), _m(sel, "VA")
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2
    if _m(sel, "MSI") == "S" or _m(sel, "MSA") == "S":
        eq4 = 0
    elif _m(sel, "SC") == "H" or _m(sel, "SI") == "H" or _m(sel, "SA") == "H":
        eq4 = 1
    else:
        eq4 = 2
    eq5 = {"A": 0, "P": 1, "U": 2}[_m(sel, "E")]
    cr, ir, ar = _m(sel, "CR"), _m(sel, "IR"), _m(sel, "AR")
    eq6 = 0 if ((cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H")) else 1
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

def _extract(metric: str, max_vector: str) -> str:
    idx = max_vector.index(metric + ":") + len(metric) + 1
    rest = max_vector[idx:]
    return rest.split("/", 1)[0]

def _js_round1(value: float) -> float:
    return math.floor(value * 10 + 0.5) / 10

def _decimal_round1(value: float) -> float:
    normalized = Decimal(f"{value:.{ROUNDING_PRECISION_DECIMALS}f}")
    return float(normalized.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))

def _round1(value: float, rounding: str) -> float:
    if rounding == "decimal":
        return _decimal_round1(value)
    if rounding == "js":
        return _js_round1(value)
    if rounding == "none":
        return value
    raise ValueError(f"Bilinmeyen yuvarlama politikası: {rounding}")

def score_from_metrics(sel: dict[str, str], rounding: str = DEFAULT_ROUNDING) -> float:
    if all(_m(sel, m) == "N" for m in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    mv = macro_vector(sel)
    value = CVSS_LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def lk(key: str) -> float:
        return CVSS_LOOKUP.get(key, math.nan)

    s_eq1 = lk(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}")
    s_eq2 = lk(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}")
    if eq3 == 1 and eq6 == 1:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 0 and eq6 == 1:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")
    elif eq3 == 1 and eq6 == 0:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
    elif eq3 == 0 and eq6 == 0:
        left = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}")
        right = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}")

        s_eq3eq6 = left if left > right else right
    else:
        s_eq3eq6 = lk(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}")
    s_eq4 = lk(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}")
    s_eq5 = lk(f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}")

    eq1_maxes = MAX_COMPOSED["eq1"][str(eq1)]
    eq2_maxes = MAX_COMPOSED["eq2"][str(eq2)]
    eq3eq6_maxes = MAX_COMPOSED["eq3"][str(eq3)][str(eq6)]
    eq4_maxes = MAX_COMPOSED["eq4"][str(eq4)]
    eq5_maxes = MAX_COMPOSED["eq5"][str(eq5)]

    dist: dict[str, float] = {}
    for a in eq1_maxes:
        for b in eq2_maxes:
            for c in eq3eq6_maxes:
                for d in eq4_maxes:
                    for e in eq5_maxes:
                        max_vector = a + b + c + d + e
                        cand = {met: LEVELS[met][_m(sel, met)] - LEVELS[met][_extract(met, max_vector)] for met in LEVELS}
                        if any(v < 0 for v in cand.values()):
                            continue
                        dist = cand
                        break
                    if dist:
                        break
                if dist:
                    break
            if dist:
                break
        if dist:
            break
    if not dist:
        dist = {met: 0.0 for met in LEVELS}

    cur_eq1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur_eq2 = dist["AC"] + dist["AT"]
    cur_eq3eq6 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    cur_eq4 = dist["SC"] + dist["SI"] + dist["SA"]
    step = 0.1

    avail = {
        "eq1": value - s_eq1, "eq2": value - s_eq2, "eq3eq6": value - s_eq3eq6,
        "eq4": value - s_eq4, "eq5": value - s_eq5,
    }
    max_sev = {
        "eq1": MAX_SEVERITY["eq1"][str(eq1)] * step,
        "eq2": MAX_SEVERITY["eq2"][str(eq2)] * step,
        "eq3eq6": MAX_SEVERITY["eq3eq6"][str(eq3)][str(eq6)] * step,
        "eq4": MAX_SEVERITY["eq4"][str(eq4)] * step,
    }
    n_existing = 0
    normalized = 0.0
    for key, cur in (("eq1", cur_eq1), ("eq2", cur_eq2), ("eq3eq6", cur_eq3eq6), ("eq4", cur_eq4)):
        if not math.isnan(avail[key]):
            n_existing += 1
            normalized += avail[key] * (cur / max_sev[key])
    if not math.isnan(avail["eq5"]):
        n_existing += 1
    mean_distance = 0.0 if n_existing == 0 else normalized / n_existing
    value -= mean_distance
    value = min(max(value, 0.0), 10.0)
    return _round1(value, rounding)

def _with_groups(sel: dict[str, str], keep: list[str]) -> dict[str, str]:
    out = {m: sel[m] for m in BASE_METRICS}
    for m in THREAT_METRICS + ENV_METRICS + SUPPLEMENTAL_METRICS:
        out[m] = sel[m] if m in keep else "X"
    return out

def score_v40(vector: str, rounding: str = DEFAULT_ROUNDING) -> float:
    return score_from_metrics(parse_vector_v40(vector), rounding)

def base_score_v40(vector: str, rounding: str = DEFAULT_ROUNDING) -> float:
    return score_from_metrics(_with_groups(parse_vector_v40(vector), []), rounding)

def bt_score_v40(vector: str, rounding: str = DEFAULT_ROUNDING) -> float:
    return score_from_metrics(_with_groups(parse_vector_v40(vector), THREAT_METRICS), rounding)

def threat_metric(vector: str) -> str | None:
    value = parse_vector_v40(vector).get("E", "X")
    return None if value == "X" else value

def metric_group(metric: str) -> str:
    if metric in BASE_METRICS:
        return "base"
    if metric in THREAT_METRICS:
        return "threat"
    if metric in ENV_METRICS:
        return "environmental"
    if metric in SUPPLEMENTAL_METRICS:
        return "supplemental"
    return "unknown"

def severity_v40(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

def try_base_score_v40(vector: Any) -> float | None:
    try:
        return base_score_v40(str(vector))
    except (Cvss40ParseError, KeyError, ValueError):
        return None

def try_bt_score_v40(vector: Any) -> float | None:
    try:
        return bt_score_v40(str(vector))
    except (Cvss40ParseError, KeyError, ValueError):
        return None

__all__ = ["REFERENCE_VERSION", "ROUNDING_PRECISION_DECIMALS", "DEFAULT_ROUNDING", "parse_vector_v40", "macro_vector",
           "score_v40", "base_score_v40", "bt_score_v40", "threat_metric", "metric_group", "severity_v40",
           "try_base_score_v40", "try_bt_score_v40", "Cvss40ParseError"]
