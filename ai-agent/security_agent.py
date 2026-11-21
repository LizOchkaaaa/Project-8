import json
import os
from pathlib import Path

from openai import OpenAI


def parse_all_reports(reports_dir: str) -> list[dict]:
    findings = []
    base = Path(reports_dir)

    # Pytest
    pytest_file = base / "pytest-report" / "pytest.json"
    if pytest_file.exists():
        data = json.loads(pytest_file.read_text(encoding="utf-8"))
        for test in data.get("tests", []):
            if test.get("outcome") == "failed":
                call_info = test.get("call", {})
                crash_msg = call_info.get("crash", {}).get("message", "")
                longrepr = str(call_info.get("longrepr", ""))
                error_details = (
                    f"{crash_msg}\n\n{longrepr[-1000:]}"
                    if crash_msg
                    else longrepr[-1000:]
                )
                findings.append(
                    {
                        "tool": "pytest (Unit Tests)",
                        "test": test.get("nodeid"),
                        "error": error_details.strip(),
                    }
                )

    # Bandit
    sast_file = base / "sast-report" / "sast.json"
    if sast_file.exists():
        data = json.loads(sast_file.read_text(encoding="utf-8"))
        for res in data.get("results", []):
            findings.append(
                {
                    "tool": "Bandit (SAST)",
                    "rule": res.get("test_name"),
                    "severity": res.get("issue_severity"),
                    "location": f"{res.get('filename')}:{res.get('line_number')}",
                    "message": res.get("issue_text"),
                }
            )

    # SCA
    sca_file = base / "sca-report" / "sca.json"
    if sca_file.exists():
        data = json.loads(sca_file.read_text(encoding="utf-8"))
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        for dep in deps:
            for vuln in dep.get("vulns", []):
                findings.append(
                    {
                        "tool": "pip-audit (Python SCA)",
                        "package": f"{dep.get('name')}=={dep.get('version')}",
                        "cve": vuln.get("id"),
                        "fix_versions": vuln.get("fix_versions"),
                    }
                )

    # Trivy
    trivy_file = base / "image-report" / "image.json"
    if trivy_file.exists():
        data = json.loads(trivy_file.read_text(encoding="utf-8"))
        for result in data.get("Results", []):
            target = result.get("Target")
            for vuln in result.get("Vulnerabilities", []):
                findings.append(
                    {
                        "tool": "Trivy (Docker SCA)",
                        "target": target,
                        "package": f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')}",
                        "cve": vuln.get("VulnerabilityID"),
                        "severity": vuln.get("Severity"),
                        "fixed_version": vuln.get("FixedVersion", "нет исправления"),
                    }
                )

    # OWASP ZAP
    zap_file = base / "zap-report" / "report.json"
    if zap_file.exists():
        data = json.loads(zap_file.read_text(encoding="utf-8"))
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                findings.append(
                    {
                        "tool": "OWASP ZAP (DAST)",
                        "rule": alert.get("name"),
                        "risk": alert.get("riskdesc"),
                        "urls": [i.get("uri") for i in alert.get("instances", [])[:3]],
                        "solution": alert.get("solution"),
                    }
                )

    return findings


def format_github_summary(findings: list[dict], ai_plan: str) -> str:
    tools_count: dict[str, int] = {}
    for item in findings:
        tool = item.get("tool", "Unknown")
        tools_count[tool] = tools_count.get(tool, 0) + 1

    stats_rows = "\n".join(
        f"| **{tool}** | `{count}` |" for tool, count in tools_count.items()
    )

    template_path = Path(__file__).parent / "report_template.md"
    template = template_path.read_text(encoding="utf-8")

    return template.format(
        stats_rows=stats_rows,
        ai_plan=ai_plan,
        raw_json=json.dumps(findings, ensure_ascii=False, indent=2),
    )


def generate_fix_plan(findings: list[dict]) -> str:
    if not findings:
        return "Все проверки пройдены или отчеты об ошибках пусты"

    client = OpenAI(
        api_key=os.environ["LLM_API_KEY"],
        base_url=os.environ.get("LLM_BASE_URL", "https://routerai.ru/api/v1"),
    )

    system_prompt = (
        "Ты — DevSecOps-инженер. Проанализируй отчеты упавших проверок из CI/CD.\n"
        "Оформи ответ максимально красиво и наглядно для GitHub Markdown:\n"
        "1. Используй эмодзи-индикаторы критичности: 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🔵 INFO.\n"
        "2. В начале сделай краткую таблицу «План действий».\n"
        "3. Объединяй связанные проблемы из разных сканеров в одну корневую причину.\n"
        "4. Длинные примеры исправленного кода оборачивай в HTML-спойлер:\n"
        "   <details><summary>Показать готовый патч</summary>\n\n   ```python\n   ...\n   ```\n   </details>\n"
        "5. Пиши кратко, без воды, на русском языке."
    )

    response = client.chat.completions.create(
        model=os.environ.get("LLM_MODEL", "deepseek/deepseek-v4.1-flash"),
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Данные проверок:\n{json.dumps(findings, ensure_ascii=False)}",
            },
        ],
        temperature=0.2,
    )
    return response.choices[0].message.content or "Не удалось получить ответ от модели"


if __name__ == "__main__":
    all_findings = parse_all_reports("downloaded-reports")
    report_md = generate_fix_plan(all_findings)

    full_report = format_github_summary(all_findings, report_md)
    print(full_report)

    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(full_report)

    Path("ai-report.md").write_text(full_report, encoding="utf-8")
