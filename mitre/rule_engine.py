"""
rule_engine.py — Deterministic MITRE ATT&CK Rule Engine (Mohamed's AI categories)
──────────────────────────────────────────────────────────────────────────────
Self-contained copy of the rule-evaluation pattern used elsewhere in the
project, scoped to this ai_engine/ directory only (malware, network, browser).
Does not import from or depend on anything in my_friend/.

Loads category-specific rules from JSON files under ai_engine/mitre/rules/
and evaluates them against a flat feature vector. Rules use AND-logic for
their conditions: every condition must match for the rule to fire.

Resilience guarantees
---------------------
* Never crashes on invalid input — malformed rules are skipped with a
  logged warning.
* Missing features default to 0 (numeric context).
* Unsupported operators log a warning and the condition is skipped.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s — %(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)
    logger.setLevel(logging.WARNING)

SUPPORTED_OPERATORS = frozenset(
    {">", "<", ">=", "<=", "==", "!=", "contains", "exists", "not_exists"}
)

REQUIRED_RULE_FIELDS = frozenset(
    {
        "rule_id", "rule_name", "description", "category", "severity",
        "base_confidence", "mitre_technique_id", "mitre_technique_name",
        "mitre_tactic", "conditions", "recommendation",
    }
)

VALID_SEVERITIES = frozenset({"Critical", "High", "Medium", "Low"})
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class RuleCondition:
    feature: str
    operator: str
    value: Any


@dataclass(frozen=True)
class MitreRule:
    rule_id: str
    rule_name: str
    description: str
    category: str
    severity: str
    base_confidence: float
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    conditions: List[RuleCondition]
    recommendation: str


@dataclass
class RuleMatch:
    rule: MitreRule
    matched_conditions: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    severity: str = "Low"


class RuleEngine:
    """Deterministic rule evaluation engine for Mohamed's categories (malware, network, browser)."""

    def __init__(self, rules_dir: str = None) -> None:
        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
        self.rules_dir: str = rules_dir
        self._cache: Dict[str, List[MitreRule]] = {}

    def load_rules(self, category: str) -> List[MitreRule]:
        if category in self._cache:
            return self._cache[category]

        rules_path = os.path.join(self.rules_dir, f"{category}_rules.json")
        if not os.path.isfile(rules_path):
            logger.warning("Rules file not found: %s — returning empty rule set", rules_path)
            return []

        try:
            with open(rules_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read rules file %s: %s", rules_path, exc)
            return []

        raw_rules: list = data.get("rules", [])
        if not isinstance(raw_rules, list):
            logger.warning("'rules' key in %s is not a list — skipping file", rules_path)
            return []

        parsed: List[MitreRule] = []
        seen_ids: set = set()
        for idx, raw in enumerate(raw_rules):
            rule = self._parse_rule(raw, rules_path, idx, seen_ids)
            if rule is not None:
                parsed.append(rule)
                seen_ids.add(rule.rule_id)

        logger.info("Loaded %d valid rules for category '%s'", len(parsed), category)
        self._cache[category] = parsed
        return parsed

    def evaluate(self, category: str, feature_vector: dict, prediction: dict = None) -> List[RuleMatch]:
        rules = self.load_rules(category)
        if not rules:
            return []
        if feature_vector is None:
            feature_vector = {}

        matches: List[RuleMatch] = []
        for rule in rules:
            match = self._evaluate_rule(rule, feature_vector, prediction)
            if match is not None:
                matches.append(match)
        return matches

    def _parse_rule(self, raw: Any, source: str, index: int, seen_ids: set) -> Optional[MitreRule]:
        if not isinstance(raw, dict):
            logger.warning("%s rule #%d: expected dict, got %s — skipping", source, index, type(raw).__name__)
            return None

        missing = REQUIRED_RULE_FIELDS - raw.keys()
        if missing:
            logger.warning("%s rule #%d (%s): missing fields %s — skipping", source, index, raw.get("rule_id", "?"), sorted(missing))
            return None

        rule_id = raw["rule_id"]
        if rule_id in seen_ids:
            logger.warning("%s rule #%d: duplicate rule_id '%s' — skipping", source, index, rule_id)
            return None

        severity = raw["severity"]
        if severity not in VALID_SEVERITIES:
            logger.warning("%s rule '%s': invalid severity '%s' — skipping", source, rule_id, severity)
            return None

        try:
            base_confidence = float(raw["base_confidence"])
        except (TypeError, ValueError):
            logger.warning("%s rule '%s': base_confidence is not numeric — skipping", source, rule_id)
            return None
        if not 0.0 <= base_confidence <= 1.0:
            logger.warning("%s rule '%s': base_confidence %.4f outside [0,1] — skipping", source, rule_id, base_confidence)
            return None

        technique_id = str(raw["mitre_technique_id"])
        if not TECHNIQUE_ID_RE.match(technique_id):
            logger.warning("%s rule '%s': mitre_technique_id '%s' does not match T####(.###) — skipping", source, rule_id, technique_id)
            return None

        raw_conditions = raw.get("conditions", [])
        if not isinstance(raw_conditions, list) or len(raw_conditions) == 0:
            logger.warning("%s rule '%s': conditions must be a non-empty list — skipping", source, rule_id)
            return None

        conditions: List[RuleCondition] = []
        for cidx, cond in enumerate(raw_conditions):
            parsed_cond = self._parse_condition(cond, source, rule_id, cidx)
            if parsed_cond is not None:
                conditions.append(parsed_cond)

        if not conditions:
            logger.warning("%s rule '%s': no valid conditions after parsing — skipping", source, rule_id)
            return None

        return MitreRule(
            rule_id=str(rule_id),
            rule_name=str(raw["rule_name"]),
            description=str(raw["description"]),
            category=str(raw["category"]),
            severity=severity,
            base_confidence=base_confidence,
            mitre_technique_id=technique_id,
            mitre_technique_name=str(raw["mitre_technique_name"]),
            mitre_tactic=str(raw["mitre_tactic"]),
            conditions=conditions,
            recommendation=str(raw["recommendation"]),
        )

    @staticmethod
    def _parse_condition(cond: Any, source: str, rule_id: str, index: int) -> Optional[RuleCondition]:
        if not isinstance(cond, dict):
            logger.warning("%s rule '%s' cond #%d: expected dict — skipping", source, rule_id, index)
            return None
        for key in ("feature", "operator", "value"):
            if key not in cond:
                logger.warning("%s rule '%s' cond #%d: missing '%s' — skipping", source, rule_id, index, key)
                return None
        operator = cond["operator"]
        if operator not in SUPPORTED_OPERATORS:
            logger.warning("%s rule '%s' cond #%d: unsupported operator '%s' — skipping", source, rule_id, index, operator)
            return None
        return RuleCondition(feature=str(cond["feature"]), operator=str(operator), value=cond["value"])

    def _evaluate_rule(self, rule: MitreRule, feature_vector: dict, prediction: Optional[dict]) -> Optional[RuleMatch]:
        matched_conditions: List[Dict[str, Any]] = []
        for condition in rule.conditions:
            if not self._evaluate_condition(condition, feature_vector):
                return None
            actual = self._get_feature_value(condition.feature, feature_vector)
            matched_conditions.append({
                "feature": condition.feature, "operator": condition.operator,
                "expected": condition.value, "actual": actual,
            })

        confidence = self._calculate_confidence(rule, matched_conditions, prediction)
        severity = self._determine_severity(rule, confidence)
        return RuleMatch(rule=rule, matched_conditions=matched_conditions, confidence=round(confidence, 4), severity=severity)

    def _evaluate_condition(self, condition: RuleCondition, feature_vector: dict) -> bool:
        feature_val = self._get_feature_value(condition.feature, feature_vector)
        op = condition.operator
        threshold = condition.value

        try:
            if op == "exists":
                return feature_val is not None and feature_val != 0
            if op == "not_exists":
                return feature_val is None or feature_val == 0
            if op == "contains":
                if feature_val is None:
                    return False
                return str(threshold) in str(feature_val)

            num_feature = self._to_numeric(feature_val)
            num_threshold = self._to_numeric(threshold)

            if num_feature is not None and num_threshold is not None:
                if op == ">":
                    return num_feature > num_threshold
                if op == "<":
                    return num_feature < num_threshold
                if op == ">=":
                    return num_feature >= num_threshold
                if op == "<=":
                    return num_feature <= num_threshold
                if op == "==":
                    return num_feature == num_threshold
                if op == "!=":
                    return num_feature != num_threshold
            else:
                str_feature = "" if feature_val is None else str(feature_val)
                str_threshold = str(threshold)
                if op == "==":
                    return str_feature == str_threshold
                if op == "!=":
                    return str_feature != str_threshold
                logger.warning("Cannot apply operator '%s' to non-numeric values — treating as False", op)
                return False
        except Exception as exc:
            logger.warning("Unexpected error evaluating condition %s %s %s: %s", condition.feature, op, threshold, exc)
            return False

        return False

    def _calculate_confidence(self, rule: MitreRule, matched_conditions: list, prediction: Optional[dict] = None) -> float:
        confidence = rule.base_confidence

        exceedance_boosts: List[float] = []
        for mc in matched_conditions:
            if mc.get("operator", "") not in (">", ">="):
                continue
            actual = self._to_numeric(mc.get("actual"))
            expected = self._to_numeric(mc.get("expected"))
            if actual is not None and expected is not None and expected != 0:
                ratio = (actual - expected) / abs(expected)
                if ratio > 0:
                    exceedance_boosts.append(min(ratio * 0.05, 0.15))
        if exceedance_boosts:
            confidence += sum(exceedance_boosts) / len(exceedance_boosts)

        if prediction and isinstance(prediction, dict):
            anomaly_score = self._to_numeric(prediction.get("anomaly_score"))
            if anomaly_score is not None and anomaly_score > 0.5:
                confidence += min((anomaly_score - 0.5) * 0.2, 0.10)

        return max(0.0, min(1.0, confidence))

    def _determine_severity(self, rule: MitreRule, confidence: float) -> str:
        severity_order = ["Low", "Medium", "High", "Critical"]
        try:
            idx = severity_order.index(rule.severity)
        except ValueError:
            return rule.severity
        if confidence >= 0.90 and idx < len(severity_order) - 1:
            return severity_order[idx + 1]
        if confidence < 0.40 and idx > 0:
            return severity_order[idx - 1]
        return rule.severity

    @staticmethod
    def _get_feature_value(feature_name: str, feature_vector: dict) -> Any:
        if feature_vector is None:
            return 0
        return feature_vector.get(feature_name, 0)

    @staticmethod
    def _to_numeric(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
