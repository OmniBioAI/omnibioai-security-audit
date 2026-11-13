"""Fresh-clone packaging and release-provenance regression checks."""

import tomllib
from importlib.metadata import version
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

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


CORE_PACKAGES = (
    "alembic",
    "cryptography",
    "fastapi",
    "pydantic",
    "pymysql",
    "redis",
    "sqlalchemy",
    "starlette",
    "uvicorn",
)


def _constraints() -> dict[str, str]:
    pins = {}
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            name, _, pinned = line.partition("==")
            assert pinned, f"constraints.txt entry is not an exact pin: {line}"
            pins[canonicalize_name(name)] = pinned
    return pins


def test_worker_image_installs_with_constraints() -> None:
    dockerfile = (ROOT / "Dockerfile.worker").read_text(encoding="utf-8")
    assert "pip install --no-cache-dir -c constraints.txt ." in dockerfile


def test_constraints_pin_every_core_package() -> None:
    pins = _constraints()
    missing = [name for name in CORE_PACKAGES if name not in pins]
    assert not missing


def test_pyproject_ranges_admit_constrained_versions() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pins = _constraints()
    for dependency in project["project"]["dependencies"]:
        requirement = Requirement(dependency)
        pinned = pins.get(canonicalize_name(requirement.name))
        assert pinned is not None, f"{requirement.name} missing from constraints.txt"
        assert requirement.specifier.contains(pinned, prereleases=True), (
            f"{requirement} does not allow constrained {pinned}"
        )
