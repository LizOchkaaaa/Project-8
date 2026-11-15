from .model import recommend
from .parsers import SCANNERS, read_reports
from .policy import evaluate, group_findings, load_policy


def analyze(
    directory, *, offline=False, config=None, policy=None, scanners=SCANNERS, pipeline=None
):
    findings, states = read_reports(directory, scanners)
    groups = group_findings(findings)
    return {
        "schema_version": 1,
        "gate": evaluate(
            findings, states, policy if policy is not None else load_policy(), pipeline
        ),
        "scans": states,
        "groups": groups,
        "advisory": recommend(groups, offline=offline, config=config),
    }
