"""python -m security_assistant --reports reports --output analysis [--offline]."""

import argparse
import json
from pathlib import Path

from .model import recommend
from .parsers import SCANNERS, ReportError, load_json, read_reports
from .policy import DEFAULT_POLICY, evaluate, group_findings, load_policy


class CLIParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Некорректные параметры. Укажите --reports и --output; справка: --help.\n")


def markdown(analysis):
    gate, advisory = analysis["gate"], analysis["advisory"]
    lines = [
        "# Разбор проверок безопасности",
        "",
        f"Допуск по policy: {gate['status']}",
        f"Область: {gate['scope']}. Импортированный отчёт не разрешает реальный выпуск.",
        "",
        advisory["message"],
        "",
        "## Состояние сканов",
        "",
    ]
    for scanner, state in analysis["scans"].items():
        lines.append(f"- {scanner}: {state['status']}, замечаний {state['count']}")
    if gate["failures"]:
        lines.extend(["", "## Ошибки pipeline и полноты проверок", ""])
        lines.extend("- " + failure for failure in gate["failures"])
    groups = {g["id"]: g for g in analysis["groups"]}
    lines.extend(["", "## Порядок исправлений", ""])
    for recommendation in advisory["recommendations"]:
        group = groups[recommendation["group_id"]]
        # JSON-кодирование + fenced block не превращают scanner text в Markdown links/HTML.
        lines.extend(
            [
                f"### {recommendation['order']}. {group['id']} ({group['severity']})",
                "",
                "```json",
                json.dumps(
                    {
                        "reason": recommendation["reason"],
                        "action": recommendation["action"],
                        "primary_ids": group["primary_ids"],
                        "package": group["package"],
                        "fixed_versions": group["fixed_versions"],
                        "sources": [
                            {k: r[k] for k in ("scanner", "id", "file", "line", "target")}
                            for r in group["evidence"]
                        ],
                    },
                    ensure_ascii=True,
                    indent=2,
                ),
                "```",
                "",
            ]
        )
    if not groups:
        lines.append("Замечаний нет. Это не подтверждает полноту отсутствующих проверок.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = CLIParser(description="Разбор security reports и независимый policy gate")
    parser.add_argument(
        "--reports", type=Path, required=True, help="Каталог пяти известных JSON отчётов"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Каталог analysis.json и analysis.md"
    )
    parser.add_argument("--offline", action="store_true", help="Не обращаться к сети")
    parser.add_argument(
        "--gate", action="store_true", help="Вернуть exit 1 при запрете выпуска; без модели"
    )
    parser.add_argument(
        "--scanner", choices=SCANNERS, help="Проверить один scanner в отдельной CI job"
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--pipeline", type=Path, help="JSON результатов всех обязательных CI jobs")
    args = parser.parse_args(argv)
    if args.scanner and not args.gate:
        parser.error("--scanner разрешён только вместе с --gate")
    try:
        policy = load_policy(args.policy)
        scanners = (args.scanner,) if args.scanner else SCANNERS
        findings, states = read_reports(args.reports, scanners)
        if args.scanner:
            policy = {**policy, "required_scanners": [args.scanner]}
        pipeline = load_json(args.pipeline, 16000) if args.pipeline else None
        gate = evaluate(findings, states, policy, pipeline)
        groups = group_findings(findings)
        advisory = recommend(groups, offline=args.offline or args.gate)
        analysis = {
            "schema_version": 1,
            "gate": gate,
            "scans": states,
            "groups": groups,
            "advisory": advisory,
        }
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "analysis.json").write_text(
            json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (args.output / "analysis.md").write_text(markdown(analysis), encoding="utf-8")
        print(
            f"Разбор сохранён. Policy: {gate['status']}. Источник рекомендаций: {advisory['mode']}."
        )
        return 1 if args.gate and gate["status"] == "blocked" else 0
    except (ReportError, OSError, ValueError, TypeError, KeyError):
        print("Не удалось обработать policy, pipeline или сохранить результат. Выпуск запрещён.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
