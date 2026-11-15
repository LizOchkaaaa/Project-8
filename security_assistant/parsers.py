"""Строгое чтение пяти известных JSON-форматов без исходного кода и секретов."""

import hashlib
import json
import re
from pathlib import Path

SCANNERS = ("gitleaks", "bandit", "pip-audit", "trivy", "zap")
MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2000
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "unknown": 3, "high": 4, "critical": 5}
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!:@/~-]{0,199}\Z")
ADVISORY = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\Z", re.I)


class ReportError(ValueError):
    pass


def obj(value):
    if not isinstance(value, dict):
        raise ReportError("Ожидается JSON-объект")
    return value


def rows(value):
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise ReportError("Некорректный список или превышен лимит записей")
    return value


def string(value, limit=500):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ReportError("Некорректное текстовое поле")
    if any(not c.isprintable() for c in value):
        raise ReportError("Управляющие символы в текстовом поле")
    return value.strip()


def token(value):
    value = string(value, 200)
    if not TOKEN.fullmatch(value):
        raise ReportError("Некорректный идентификатор")
    return value


def line(value):
    if type(value) is not int or value < 0 or value > 10000000:
        raise ReportError("Некорректный номер строки")
    return value


def severity(value):
    if not isinstance(value, str):
        raise ReportError("Некорректная severity")
    return value.lower() if value.lower() in SEVERITIES else "unknown"


def versions(values):
    return sorted({token(v) for v in rows(values)})


def finding(
    scanner,
    rule,
    level,
    *,
    file="",
    lineno=0,
    package="",
    version="",
    ecosystem="",
    target="",
    aliases=None,
    fixed=None,
):
    rule = token(rule)
    return {
        "scanner": scanner,
        "primary_id": rule,
        "rule": rule,
        "severity": severity(level),
        "aliases": sorted(set(aliases or [])),
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "target": target,
        "file": file,
        "line": lineno,
        "fixed_versions": fixed or [],
        "title": "Возможное раскрытие секрета"
        if scanner == "gitleaks"
        else "Запуск команды через shell"
        if scanner == "bandit" and rule == "B602"
        else "Уязвимость зависимости"
        if scanner in {"pip-audit", "trivy"}
        else "Замечание проверки безопасности",
    }


def parse_gitleaks(data):
    return [
        finding(
            "gitleaks",
            obj(r)["RuleID"],
            "critical",
            file=string(r["File"]),
            lineno=line(r["StartLine"]),
        )
        for r in rows(data)
    ]


def parse_bandit(data):
    data = obj(data)
    if rows(data["errors"]):
        raise ReportError("Bandit сообщил об ошибках обработки")
    metrics = obj(data["metrics"])
    if not obj(metrics["_totals"]) or type(metrics["_totals"].get("loc")) is not int:
        raise ReportError("Нет метрик обработанного кода Bandit")
    if metrics["_totals"]["loc"] <= 0:
        raise ReportError("Bandit не проверил код")
    return [
        finding(
            "bandit",
            obj(r)["test_id"],
            r["issue_severity"],
            file=string(r["filename"]),
            lineno=line(r["line_number"]),
        )
        for r in rows(data["results"])
    ]


def parse_pip(data):
    dependencies = rows(obj(data)["dependencies"])
    if not dependencies:
        raise ReportError("pip-audit не проверил зависимости")
    result = []
    for dep in dependencies:
        dep = obj(dep)
        if "skip_reason" in dep:
            raise ReportError("pip-audit пропустил зависимость")
        package, version = token(dep["name"]), token(dep["version"])
        for vuln in rows(dep["vulns"]):
            vuln = obj(vuln)
            primary = token(vuln["id"])
            aliases = [token(a) for a in rows(vuln.get("aliases", []))]
            aliases.append(primary)
            result.append(
                finding(
                    "pip-audit",
                    primary,
                    vuln.get("severity", "unknown"),
                    package=package,
                    version=version,
                    ecosystem="pypi",
                    target="requirements.txt",
                    aliases=aliases,
                    fixed=versions(vuln["fix_versions"]),
                )
            )
            if len(result) > MAX_FINDINGS:
                raise ReportError("Превышен лимит замечаний pip-audit")
    return result


def parse_trivy(data):
    data = obj(data)
    if data.get("SchemaVersion") != 2 or data.get("ArtifactType") != "container_image":
        raise ReportError("Ожидается отчёт Trivy container_image schema 2")
    string(data["ArtifactName"])
    results = rows(data["Results"])
    if not results:
        raise ReportError("Trivy не содержит проверенных компонентов образа")
    findings = []
    for result in results:
        result = obj(result)
        target = string(result["Target"])
        kind = token(result["Type"])
        ecosystem = "pypi" if kind == "python-pkg" else kind
        if result.get("Class") not in {"os-pkgs", "lang-pkgs"}:
            raise ReportError("Неизвестный класс проверки Trivy")
        for vuln in rows(result.get("Vulnerabilities", [])):
            vuln = obj(vuln)
            primary = token(vuln["VulnerabilityID"])
            aliases = [primary]
            # Только идентификаторы, без URL, описаний и произвольных References.
            for alias in rows(vuln.get("VendorIDs", [])):
                if isinstance(alias, str) and ADVISORY.fullmatch(alias):
                    aliases.append(alias)
            fixed = vuln.get("FixedVersion", "")
            if not isinstance(fixed, str):
                raise ReportError("Некорректная исправленная версия")
            findings.append(
                finding(
                    "trivy",
                    primary,
                    vuln["Severity"],
                    package=token(vuln["PkgName"]),
                    version=token(vuln["InstalledVersion"]),
                    ecosystem=ecosystem,
                    target=target,
                    aliases=aliases,
                    fixed=versions([v.strip() for v in fixed.split(",") if v.strip()]),
                )
            )
            if len(findings) > MAX_FINDINGS:
                raise ReportError("Превышен лимит замечаний Trivy")
    return findings


def parse_zap(data):
    data = obj(data)
    string(data["@version"])
    sites = rows(data["site"])
    if not sites:
        raise ReportError("ZAP не содержит проверенных сайтов")
    result = []
    levels = {"0": "info", "1": "low", "2": "medium", "3": "high"}
    for site in sites:
        site = obj(site)
        target = string(site["@name"])
        for alert in rows(site["alerts"]):
            alert = obj(alert)
            risk = alert["riskcode"]
            if str(risk) not in levels:
                raise ReportError("Некорректная severity ZAP")
            instances = rows(alert["instances"])
            if not instances:
                raise ReportError("Замечание ZAP без источников")
            for instance in instances:
                # URI только в локальном evidence, никогда не становится ссылкой/запросом.
                uri = string(obj(instance)["uri"])
                result.append(
                    finding(
                        "zap", str(alert["pluginid"]), levels[str(risk)], target=target, file=uri
                    )
                )
                if len(result) > MAX_FINDINGS:
                    raise ReportError("Превышен лимит замечаний ZAP")
    return result


PARSERS = dict(zip(SCANNERS, (parse_gitleaks, parse_bandit, parse_pip, parse_trivy, parse_zap)))


def load_json(path, limit=MAX_BYTES):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ReportError("Отчёт отсутствует или не является обычным файлом")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ReportError("Отчёт пуст или превышает лимит размера")
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReportError("Некорректный JSON") from exc


def read_reports(directory, scanners=SCANNERS):
    findings, states = [], {}
    for scanner in scanners:
        try:
            parsed = PARSERS[scanner](load_json(Path(directory) / f"{scanner}.json"))
            if len(parsed) + len(findings) > MAX_FINDINGS:
                raise ReportError("Превышен общий лимит замечаний")
            for index, record in enumerate(parsed):
                canonical = json.dumps(record, sort_keys=True, ensure_ascii=True)
                record["id"] = "f-" + hashlib.sha256(canonical.encode()).hexdigest()[:20]
                # Отдельный occurrence сохраняет даже полностью одинаковые записи.
                record["occurrence"] = index + 1
            findings.extend(parsed)
            states[scanner] = {"status": "findings" if parsed else "clean", "count": len(parsed)}
        except (ReportError, OSError, KeyError, TypeError, ValueError, RecursionError):
            states[scanner] = {
                "status": "error",
                "count": 0,
                "message": "Отчёт отсутствует, повреждён или проверка неполна",
            }
    return findings, states
