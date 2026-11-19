from pathlib import Path

import yaml

from security_assistant.policy import JOBS


def test_workflow_release_dependency_graph_and_artifacts():
    path = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    for job in ("security-gate", "advisory"):
        assert jobs[job]["if"] == "always()"
        assert set(jobs[job]["needs"]) == set(JOBS)
        uploads = [s for s in jobs[job]["steps"] if "upload-artifact" in s.get("uses", "")]
        assert uploads and all(s.get("if") == "always()" for s in uploads)
    assert jobs["deploy"]["needs"] == ["security-gate"]
    assert (
        jobs["deploy"]["if"]
        == "needs.security-gate.result == 'success' && inputs.security_demo != 'fail'"
    )
    assert "needs" not in jobs["tests"]
    assert workflow["permissions"] == {"contents": "read"}
    for name in ("secret-detection", "sast", "sca", "scan-image", "dast"):
        steps = jobs[name]["steps"]
        assert any("--gate" in s.get("run", "") for s in steps)
        assert any(
            s.get("if") == "always()" and "upload-artifact" in s.get("uses", "") for s in steps
        )
    assert "cache" not in str(jobs["lint"]["steps"])
    assert "pull_request_target" not in path.read_text(encoding="utf-8")
    env = next(s["env"] for s in jobs["advisory"]["steps"] if "OPENAI_API_KEY" in s.get("env", {}))
    assert "github.event_name == 'push'" in env["OPENAI_API_KEY"]
    assert "github.ref == 'refs/heads/main'" in env["OPENAI_API_KEY"]


def test_review_push_uses_same_release_gate_for_the_rejection_rehearsal():
    directory = Path(__file__).resolve().parent.parent / ".github/workflows"
    release = yaml.safe_load((directory / "ci.yml").read_text(encoding="utf-8"))
    rehearsal = yaml.safe_load((directory / "release-rejection.yml").read_text(encoding="utf-8"))
    branch = "feature/review-workspace"
    assert branch in release[True]["push"]["branches"]
    assert rehearsal[True]["push"]["branches"] == [branch]
    assert rehearsal["jobs"]["reject"] == {
        "uses": "./.github/workflows/ci.yml",
        "with": {"security_demo": "fail"},
    }
    assert any(
        "--verify-rejection" in step.get("run", "")
        for step in release["jobs"]["security-gate"]["steps"]
    )
