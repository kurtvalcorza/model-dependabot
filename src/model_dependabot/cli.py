"""The command frame: argument parsing, text and JSON output and exit codes (contracts/cli.md).

Every command accepts ``--db PATH`` and ``--json``, before or after the command name. A command is a
handler that takes the parsed arguments and returns a ``CommandResult``; the frame prints it and
turns the outcome into an exit code: 0 success, 1 invalid input, 2 a source failed, 3 an unexpected
error. No command changes a model or writes to a model's repository (FR-017).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from model_dependabot.sources.fetcher import SourceFailedError
from model_dependabot.store import DISMISSAL_REASONS

EXIT_OK = 0
EXIT_INVALID_INPUT = 1
EXIT_SOURCE_FAILED = 2
EXIT_UNEXPECTED = 3

DEFAULT_DB = "./model-dependabot.db"
CHECK_SOURCES = ("osv", "picklescan", "hf-scan")

COMMANDS = (
    "register",
    "import",
    "inventory show",
    "inventory export",
    "check",
    "policy",
    "alerts",
    "alert show",
    "alert dismiss",
    "history",
)


@dataclass(frozen=True)
class CommandResult:
    """What a command produced: ``payload`` for ``--json``, ``text`` for people."""

    payload: Mapping[str, Any]
    text: str
    sources_failed: bool = False


class InvalidInputError(Exception):
    """The manifest, inventory or arguments are not valid (exit code 1)."""


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(f"{self.prog}: {message}")


Handler = Callable[[argparse.Namespace], CommandResult]

# Filled in as each command is built; a command without a handler exits 3.
DEFAULT_HANDLERS: dict[str, Handler] = {}


def _sources(text: str) -> list[str]:
    names = [name.strip() for name in text.split(",") if name.strip()]
    unknown = [name for name in names if name not in CHECK_SOURCES]
    if not names or unknown:
        raise argparse.ArgumentTypeError(
            f"sources must be from {', '.join(CHECK_SOURCES)}; got {text!r}"
        )
    return names


def _common(suppress: bool) -> argparse.ArgumentParser:
    common = _Parser(add_help=False)
    db_default = argparse.SUPPRESS if suppress else DEFAULT_DB
    json_default = argparse.SUPPRESS if suppress else False
    common.add_argument(
        "--db", default=db_default, metavar="PATH", help=f"database file (default {DEFAULT_DB})"
    )
    common.add_argument(
        "--json", action="store_true", default=json_default, help="machine-readable output"
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common(suppress=True)
    parser = _Parser(
        prog="model-dependabot",
        description="Dependency alerts for AI models.",
        parents=[_common(suppress=False)],
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def leaf(group: Any, name: str, key: str, help_text: str) -> argparse.ArgumentParser:
        sub = group.add_parser(name, parents=[common], help=help_text, description=help_text)
        sub.set_defaults(command_key=key)
        return sub

    register = leaf(commands, "register", "register", "register a model or a new version")
    register.add_argument("manifest", metavar="MANIFEST.toml")
    register.add_argument("--model-id", metavar="ID")

    imported = leaf(commands, "import", "import", "register a version from a CycloneDX inventory")
    imported.add_argument("bom", metavar="BOM.json")
    imported.add_argument("--model-id", metavar="ID", required=True)

    inventory = commands.add_parser("inventory", help="show or export an inventory")
    inventory_commands = inventory.add_subparsers(dest="inventory_command", required=True)
    show = leaf(inventory_commands, "show", "inventory show", "list entries and gaps")
    show.add_argument("model_id", metavar="ID")
    show.add_argument("--version", type=int, metavar="N")
    export = leaf(inventory_commands, "export", "inventory export", "write CycloneDX 1.7 JSON")
    export.add_argument("model_id", metavar="ID")
    export.add_argument("--version", type=int, metavar="N")
    export.add_argument("-o", dest="output", metavar="FILE", required=True)

    check = leaf(commands, "check", "check", "run the checks now")
    check.add_argument("model_id", metavar="ID", nargs="?")
    check.add_argument("--all", action="store_true", help="check every model's current version")
    check.add_argument(
        "--source",
        dest="sources",
        type=_sources,
        default=list(CHECK_SOURCES),
        metavar=",".join(CHECK_SOURCES),
    )

    policy = leaf(commands, "policy", "policy", "set a model's format policy")
    policy.add_argument("model_id", metavar="ID")
    policy.add_argument("--format", choices=("default", "strict"), required=True)
    policy.add_argument("--by", metavar="NAME", required=True)

    alerts = leaf(commands, "alerts", "alerts", "list alerts, then watch events")
    alerts.add_argument("model_id", metavar="ID")
    alerts.add_argument("--state", choices=("open", "closed", "all"), default="open")

    alert = commands.add_parser("alert", help="show or dismiss one alert")
    alert_commands = alert.add_subparsers(dest="alert_command", required=True)
    alert_show = leaf(alert_commands, "show", "alert show", "one alert with all its evidence")
    alert_show.add_argument("alert_id", metavar="ALERT_ID", type=int)
    dismiss = leaf(alert_commands, "dismiss", "alert dismiss", "dismiss with a listed reason")
    dismiss.add_argument("alert_id", metavar="ALERT_ID", type=int)
    dismiss.add_argument("--reason", choices=DISMISSAL_REASONS, required=True)
    dismiss.add_argument("--note", metavar="TEXT")
    dismiss.add_argument("--by", metavar="NAME", required=True)

    history = leaf(commands, "history", "history", "closed alerts and how they closed")
    history.add_argument("model_id", metavar="ID")

    return parser


def _validate(args: argparse.Namespace) -> None:
    if args.command_key == "check" and (args.model_id is None) == (not args.all):
        raise InvalidInputError("check needs a model ID or --all, but not both")


def _report_error(code: int, message: str, as_json: bool) -> int:
    print(f"error: {message}", file=sys.stderr)
    if as_json:
        print(json.dumps({"error": {"exit_code": code, "message": message}}))
    return code


def main(
    argv: Sequence[str] | None = None, *, handlers: Mapping[str, Handler] | None = None
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    handlers = DEFAULT_HANDLERS if handlers is None else handlers
    as_json = "--json" in argv
    try:
        args = build_parser().parse_args(argv)
    except _UsageError as error:
        return _report_error(EXIT_INVALID_INPUT, str(error), as_json)
    except SystemExit as stop:  # --help
        return stop.code if isinstance(stop.code, int) else EXIT_OK

    as_json = args.json
    try:
        _validate(args)
        handler = handlers.get(args.command_key)
        if handler is None:
            raise NotImplementedError(f"the {args.command_key} command is not built yet")
        result = handler(args)
    except InvalidInputError as error:
        return _report_error(EXIT_INVALID_INPUT, str(error), as_json)
    except SourceFailedError as error:
        return _report_error(EXIT_SOURCE_FAILED, str(error), as_json)
    except Exception as error:
        return _report_error(EXIT_UNEXPECTED, f"unexpected: {error}", as_json)

    if as_json:
        print(json.dumps(result.payload, indent=2, sort_keys=False))
    elif result.text:
        print(result.text)
    return EXIT_SOURCE_FAILED if result.sources_failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
