"""Exit codes are unchanged by lineage (T039, SC-007, FR-027).

The rows of ``tests/contract/test_exit_codes.py`` that lineage touches (a valid registration, an
invalid manifest, a check with and without a failed source, the ``--fail-on`` gate) run here on
lineage fixtures. A child whose only findings are inherited exits as one with none: an inherited
finding is a watch event and never counts for ``--fail-on``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from lineage_support import Cli, manifest
from model_dependabot.cli import EXIT_GATE, EXIT_INVALID_INPUT, EXIT_OK, EXIT_SOURCE_FAILED


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    return Cli(tmp_path, capsys)


def test_the_exit_code_rows_on_lineage_fixtures(
    cli: Cli, derive_upstream: Callable[..., Path]
) -> None:
    hub = derive_upstream()
    assert cli.run("register", manifest("bad-relationship"))[0] == EXIT_INVALID_INPUT
    assert cli.run("register", manifest("both-forms"))[0] == EXIT_INVALID_INPUT
    for name in ("chain-grandparent", "chain-parent", "chain-child", "cycle-a", "duplicate"):
        assert cli.run("register", manifest(name))[0] == EXIT_OK
    assert cli.run("check", "example-cycle-a", "--source", "picklescan")[0] == EXIT_OK
    failed = derive_upstream(errors={"hf_upstream/model-disabled": "timed out"})
    code, _ = cli.run("check", "example-grand", "--source", "hf-hub", root=failed)
    assert code == EXIT_SOURCE_FAILED
    gated = cli.run("check", "example-grand", "--source", "hf-hub", "--fail-on", "LOW", root=hub)
    assert gated[0] == EXIT_GATE  # the parent's own alert counts for the parent
    # The control: a model with no parents and nothing to check, gated the same way.
    plain = Path(cli.db).parent.parent / "plain.toml"
    plain.write_text('[model]\nid = "example-plain"\n', encoding="utf-8")
    cli.ok("register", str(plain))
    control, expected = cli.run(
        "check", "example-plain", "--source", "picklescan", "--fail-on", "LOW"
    )
    for child in ("example-mid", "example-child"):
        code, payload = cli.run("check", child, "--source", "picklescan", "--fail-on", "LOW")
        assert code == control
        assert payload["gate"]["alerts"] == expected["gate"]["alerts"] == []
        assert payload["gate"]["tripped"] == expected["gate"]["tripped"]
        [model] = payload["models"]
        assert model["opened"] == [] and len(model["watch_events"]) == 1
