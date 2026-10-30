"""Fresh-clone packaging and release-provenance regression checks."""

from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_editable_distribution_is_installed() -> None:
    assert version("omnibioai-security-audit") == "0.1.0"


def test_worker_release_has_commit_provenance_contract() -> None:
    dockerfile = (ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert 'ARG VCS_REF=unknown' in dockerfile
    assert 'org.opencontainers.image.revision="${VCS_REF}"' in dockerfile
    assert "org.opencontainers.image.revision=${{ github.sha }}" in workflow
    assert "file: Dockerfile.worker" in workflow
