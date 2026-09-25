from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

CURRENT = "CURRENT"
OUTDATED = "OUTDATED"
MAIN_LABELS = frozenset({CURRENT, OUTDATED})

NOT_VISIBLE = "NOT_VISIBLE"
NOT_LABELABLE = "NOT_LABELABLE"
EXCLUDED_AMBIGUOUS = "EXCLUDED_AMBIGUOUS"
NOT_TARGET_CHAIN = "NOT_TARGET_CHAIN"

TARGET_SOURCE = "TARGET_SOURCE"
OTHER_SOURCE_CURRENT = "OTHER_SOURCE_CURRENT"
OTHER_SOURCE_INACTIVE = "OTHER_SOURCE_INACTIVE"
OTHER_CVE = "OTHER_CVE"

MAIN_REPLACEMENT_TYPES = frozenset({"STRICT_SAME_CHANGE"})

@dataclass(frozen=True)
class EvidenceView:

    evidence_id: str
    cve_id: str
    source_key: str
    cvss_version: str | None
    observed_from: str
    valid_until: str | None
    replacement_type: str | None
    chain_ambiguous: bool
    valid_from_censored: bool

    @classmethod
    def from_any(cls, e: Any) -> "EvidenceView":
        if isinstance(e, dict):
            get = e.get
        else:
            get = lambda k, d=None: getattr(e, k, d)
        return cls(
            evidence_id=get("evidence_id"), cve_id=get("cve_id"), source_key=get("source_key"),
            cvss_version=get("cvss_version"), observed_from=get("observed_from"), valid_until=get("valid_until"),
            replacement_type=get("replacement_type"), chain_ambiguous=bool(get("chain_ambiguous")),
            valid_from_censored=bool(get("valid_from_censored")),
        )

@dataclass(frozen=True)
class Query:

    cve_id: str | None
    source_key: str | None
    cvss_version: str | None
    query_time: str

def is_visible(e: EvidenceView, query_time: str) -> bool:
    return e.observed_from <= query_time

def is_active(e: EvidenceView, query_time: str) -> bool:
    return is_visible(e, query_time) and (e.valid_until is None or query_time < e.valid_until)

def in_target_chain(e: EvidenceView, q: Query) -> bool:
    return (
        (q.cve_id is None or e.cve_id == q.cve_id)
        and (q.source_key is None or e.source_key == q.source_key)
        and (q.cvss_version is None or e.cvss_version is None or e.cvss_version == q.cvss_version)
    )

def _as_query(query_time: str | Query, target_source_key: str | None, cve_id: str | None) -> Query:
    if isinstance(query_time, Query):
        return query_time
    return Query(cve_id=cve_id, source_key=target_source_key, cvss_version=None, query_time=query_time)

def label(e: Any, query_time: str | Query, target_source_key: str | None = None, cve_id: str | None = None,
          main_replacement_types: Iterable[str] = MAIN_REPLACEMENT_TYPES) -> str:
    v = EvidenceView.from_any(e)
    q = _as_query(query_time, target_source_key, cve_id)
    if not is_visible(v, q.query_time):
        return NOT_VISIBLE
    if v.chain_ambiguous:
        return EXCLUDED_AMBIGUOUS
    if not in_target_chain(v, q):
        return NOT_TARGET_CHAIN
    if is_active(v, q.query_time):
        return CURRENT
    if v.replacement_type in set(main_replacement_types):
        return OUTDATED
    return NOT_LABELABLE

def source_relation(e: Any, q: Query) -> str:
    v = EvidenceView.from_any(e)
    if q.cve_id is not None and v.cve_id != q.cve_id:
        return OTHER_CVE
    if in_target_chain(v, q):
        return TARGET_SOURCE
    return OTHER_SOURCE_CURRENT if (not v.chain_ambiguous and is_active(v, q.query_time)) else OTHER_SOURCE_INACTIVE

def graded_relevance(lbl: str, relation: str = TARGET_SOURCE) -> int:
    if lbl == CURRENT and relation == TARGET_SOURCE:
        return 2
    if relation == OTHER_SOURCE_CURRENT:
        return 1
    return 0

def binary_relevance(lbl: str, relation: str = TARGET_SOURCE) -> int:
    return 1 if (lbl == CURRENT and relation == TARGET_SOURCE) else 0

def is_stale(lbl: str) -> bool:
    return lbl == OUTDATED

def current_evidence(evidences: Iterable[Any], query_time: str, source_key: str | None = None,
                     cve_id: str | None = None) -> list[Any]:
    q = Query(cve_id=cve_id, source_key=source_key, cvss_version=None, query_time=query_time)
    out = []
    for e in evidences:
        v = EvidenceView.from_any(e)
        if v.chain_ambiguous or not is_active(v, q.query_time) or not in_target_chain(v, q):
            continue
        out.append(e)
    return out
