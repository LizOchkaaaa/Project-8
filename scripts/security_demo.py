"""Безопасный fail→pass пример: созданный код сканируется, но никогда не исполняется."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security_assistant.__main__ import main as analyze  # noqa: E402


def write_example(directory, case):
    directory.mkdir(parents=True, exist_ok=True)
    code = "def example():\n    return 'Учебный исправленный пример'\n"
    if case == "fail":
        # Строка превращается в код только во временном файле для Bandit; функция не вызывается.
        code = (
            "import subprocess\n\ndef example(command):\n"
            "    subprocess.run(command, shell=True, check=True)\n"
        )
    (directory / "example.py").write_text(code, encoding="utf-8")


def synthetic_reports(directory):
    reports = {
        "gitleaks": [],
        "pip-audit": {"dependencies": [{"name": "synthetic-demo", "version": "1.0", "vulns": []}]},
        "trivy": {
            "SchemaVersion": 2,
            "ArtifactName": "synthetic-demo",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "synthetic-demo",
                    "Class": "lang-pkgs",
                    "Type": "python-pkg",
                    "Vulnerabilities": [],
                }
            ],
        },
        "zap": {
            "@version": "synthetic-demo",
            "site": [{"@name": "http://localhost", "alerts": []}],
        },
    }
    for scanner, report in reports.items():
        (directory / f"{scanner}.json").write_text(json.dumps(report), encoding="utf-8")
    (directory / "SYNTHETIC.txt").write_text(
        "Только Bandit запущен реально. Gitleaks/pip-audit/Trivy/ZAP здесь SYNTHETIC clean fixtures.\n"
        "Это проверка parser+policy, а не разрешение удалённого выпуска.\n",
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Реальный Bandit fail→pass; остальные отчёты synthetic"
    )
    parser.add_argument("--output", type=Path, default=Path("demo-output"))
    parser.add_argument(
        "--write-example", type=Path, help="Только создать пример для реального CI SAST"
    )
    parser.add_argument("--case", choices=("none", "fail", "fixed"), default="none")
    args = parser.parse_args()
    if args.write_example:
        write_example(args.write_example, args.case)
        return 0
    for case, expected in (("fail", 1), ("fixed", 0)):
        directory = args.output.resolve() / case
        reports = directory / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        write_example(directory / "source", case)
        synthetic_reports(reports)
        # Фиксированный Python/module, без shell; аргументы путей локального CLI.
        completed = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(directory / "source"),
                "-f",
                "json",
                "-o",
                str(reports / "bandit.json"),
                "-q",
            ],
            check=False,
            timeout=60,
            capture_output=True,
        )
        if completed.returncode not in (0, 1):
            print("Не удалось запустить Bandit; demo не подтверждено.")
            return 2
        actual = analyze(
            [
                "--reports",
                str(reports),
                "--output",
                str(directory / "analysis"),
                "--gate",
                "--offline",
            ]
        )
        if actual != expected:
            print("Неожиданный результат policy; demo не подтверждено.")
            return 2
        print(
            f"{case}: реальный Bandit, policy {'BLOCK' if actual else 'PASS'}; остальные scans SYNTHETIC."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
