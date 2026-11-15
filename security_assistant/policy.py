"""Детерминированная группировка и независимый от модели допуск выпуска."""

import hashlib
import json
import re
from pathlib import Path

from .parsers import ADVISORY, SCANNERS, SEVERITIES, ReportError, load_json

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / ".security" / "policy.yml"
JOBS = ("lint", "tests", "secret-detection", "sast", "sca", "build", "scan-image", "dast")


def load_policy(path=DEFAULT_POLICY):
    policy = load_json(path, 16000)
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ReportError("Некорректная версия policy")
    if policy.get("required_scanners") != list(SCANNERS):
        raise ReportError("Policy должна требовать все пять сканеров")
    thresholds = policy.get("thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != set(SCANNERS):
        raise ReportError("Некорректные thresholds policy")
    if any(v not in {"low", "medium", "high", "critical"} for v in thresholds.values()):
        raise ReportError("Некорректный порог policy")
    if policy.get("block_unknown") is not True or policy.get("block_secrets") is not True:
        raise ReportError("Policy должна блокировать unknown и secrets")
    if policy.get("fail_closed") is not True:
        raise ReportError("Policy должна быть fail closed")
    return policy


def evaluate(findings, states, policy, pipeline=None):
    failures = [
        f"{name}: отчёт неполон или отсутствует"
        for name in policy["required_scanners"]
        if states.get(name, {}).get("status") not in {"clean", "findings"}
    ]
    blocked = []
    for record in findings:
        level = record["severity"]
        if (
            record["scanner"] == "gitleaks"
            and policy["block_secrets"]
            or level == "unknown"
            and policy["block_unknown"]
            or SEVERITIES[level] >= SEVERITIES[policy["thresholds"][record["scanner"]]]
        ):
            blocked.append(record["id"])
    if pipeline is not None:
        if not isinstance(pipeline, dict) or set(pipeline) != set(JOBS):
            failures.append("Pipeline: отсутствует полный список обязательных jobs")
        else:
            failures.extend(
                f"Pipeline: {name} = {value if isinstance(value, str) and value in {'success', 'failure', 'cancelled', 'skipped'} else 'invalid'}"
                for name, value in pipeline.items()
                if value != "success"
            )
    return {
        "status": "blocked" if failures or blocked else "passed",
        "scope": "pipeline" if pipeline is not None else "reports_only",
        "failures": failures,
        "blocked_finding_ids": sorted(set(blocked)),
    }


def package_key(record):
    package = record["package"].lower()
    if record["ecosystem"] == "pypi":
        package = re.sub(r"[-_.]+", "-", package)
    return record["ecosystem"], package, record["version"]


def group_findings(findings):
    buckets = []
    for record in sorted(findings, key=lambda r: (r["id"], r["occurrence"])):
        identifiers = {a.upper() for a in record["aliases"] if ADVISORY.fullmatch(a)}
        matching = []
        for bucket in buckets:
            first = bucket[0]
            if (
                record["scanner"] in {"pip-audit", "trivy"}
                and first["scanner"] in {"pip-audit", "trivy"}
                and package_key(record) == package_key(first)
                and identifiers.intersection(a.upper() for r in bucket for a in r["aliases"])
            ):
                matching.append(bucket)
            elif record["id"] == first["id"]:
                matching.append(bucket)
        if matching:
            merged = [record]
            for bucket in matching:
                merged.extend(bucket)
                buckets.remove(bucket)
            buckets.append(merged)
        else:
            buckets.append([record])
    groups = []
    for bucket in buckets:
        ids = sorted({r["id"] for r in bucket})
        first = bucket[0]
        group_id = "g-" + hashlib.sha256(json.dumps(ids).encode()).hexdigest()[:20]
        group = {
            "id": group_id,
            "finding_ids": ids,
            "primary_ids": sorted({r["primary_id"] for r in bucket}),
            "aliases": sorted({a for r in bucket for a in r["aliases"]}),
            "scanners": sorted({r["scanner"] for r in bucket}),
            "severity": max((r["severity"] for r in bucket), key=SEVERITIES.get),
            "package": first["package"],
            "version": first["version"],
            "ecosystem": first["ecosystem"],
            "title": first["title"],
            "fixed_versions": sorted({v for r in bucket for v in r["fixed_versions"]}),
            "evidence": bucket,
        }
        groups.append(group)
    return sorted(
        groups, key=lambda g: ("gitleaks" not in g["scanners"], -SEVERITIES[g["severity"]], g["id"])
    )


def fallback_recommendations(groups):
    result = []
    for index, group in enumerate(groups, 1):
        if "gitleaks" in group["scanners"]:
            action = "Проверьте раскрытие, отзовите действующий секрет, замените его и удалите из истории."
        elif group["package"]:
            action = "Проверьте обновление или замену зависимости и повторите связанные сканы."
        elif "bandit" in group["scanners"] and "B602" in group["primary_ids"]:
            action = "Уберите shell=True, передавайте аргументы списком и проверяйте недоверенный ввод. Повторите Bandit."
        else:
            action = "Проверьте правило и место замечания, исправьте причину и повторите скан."
        if not group["fixed_versions"] and group["package"]:
            action += " Исправленная версия в evidence не указана; уточните её у поставщика."
        result.append(
            {
                "group_id": group["id"],
                "order": index,
                "reason": "Порядок по политике: секреты, critical, high, unknown, medium, low, info.",
                "action": action,
            }
        )
    return result
