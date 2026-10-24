"""The command frame: argument parsing, text and JSON output and exit codes (contracts/cli.md).

Every command accepts ``--db PATH`` and ``--json``, before or after the command name. A command is a
handler that takes the parsed arguments and returns a ``CommandResult``; the frame prints it and
turns the outcome into an exit code: 0 success, 1 invalid input, 2 a source failed, 3 an unexpected
error. No command changes a model or writes to a model's repository (FR-017).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from model_dependabot.inventory.build import build_entries, record_licences
from model_dependabot.inventory.cyclonedx import InventoryError, export_bom, import_bom, validate
from model_dependabot.lifecycle import dismiss_alert, reevaluate_version, run_check
from model_dependabot.manifest import ManifestError, load_manifest
from model_dependabot.reports import (
    SCOPE_ALL,
    alert_line,
    alert_view,
    alerts_report,
    alerts_text,
    evidence_line,
    history_report,
    history_text,
)
from model_dependabot.sources.datacite import ensure_repository
from model_dependabot.sources.doi_ra import ensure_agency
from model_dependabot.sources.fetcher import Fetcher, SourceFailedError, UrlFetcher
from model_dependabot.store import DISMISSAL_REASONS, Store

EXIT_OK = 0
EXIT_INVALID_INPUT = 1
EXIT_SOURCE_FAILED = 2
EXIT_UNEXPECTED = 3

DEFAULT_DB = "./model-dependabot.db"
UPSTREAM_SOURCES = ("hf-hub", "hf-takedowns", "crossref", "datacite", "zenodo", "figshare")
CHECK_SOURCES = ("osv", "picklescan", "hf-scan", *UPSTREAM_SOURCES)

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
        "--scheduled",
        action="store_true",
        help="mark the run as scheduled (with --all; what the host scheduler runs)",
    )
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


# --- inventory commands (US1) ------------------------------------------------------------------


def _entry_view(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if value is not None or key == "identifier"}


def _inventory_payload(model_id: str, version: int, entries: list[dict[str, Any]]) -> dict:
    return {
        "model_id": model_id,
        "version": version,
        "entries": [_entry_view(entry) for entry in entries if entry["pinned"]],
        "gaps": [_entry_view(entry) for entry in entries if not entry["pinned"]],
    }


def _entry_label(entry: Mapping[str, Any]) -> str:
    kind = entry["kind"]
    if kind == "weight_file":
        where = entry.get("location") or f"hf:{entry.get('hub_repo')}/{entry.get('hub_file')}"
        return f"{where} [{entry['format']}]" if entry.get("format") else where
    if kind in ("package", "base_model"):
        version = entry.get("version")
        return f"{entry.get('name')}=={version}" if version else str(entry.get("name"))
    return "dataset"


def _inventory_text(payload: Mapping[str, Any], heading: str) -> str:
    lines = [heading, f"Entries ({len(payload['entries'])}):"]
    for entry in payload["entries"]:
        lines.append(f"  {entry['kind']:<12} {entry['identifier']}  {_entry_label(entry)}")
    lines.append(f"Gaps ({len(payload['gaps'])}):")
    for entry in payload["gaps"]:
        lines.append(f"  {entry['kind']:<12} {_entry_label(entry)}: {entry['gap_reason']}")
    return "\n".join(lines)


def _version_of(store: Store, model_id: str, version: int | None) -> int:
    if store.get_model(model_id) is None:
        raise InvalidInputError(f"no model {model_id!r} is registered")
    chosen = store.latest_version(model_id) if version is None else version
    if chosen is None or store.get_version(model_id, chosen) is None:
        raise InvalidInputError(f"model {model_id!r} has no version {version}")
    return chosen


def _record(
    store: Store,
    model_id: str,
    entries: list[dict[str, Any]],
    input_sha256: str,
    *,
    name: str | None = None,
    owner: str | None = None,
    base_dir: Path | None = None,
) -> int:
    """Record the next version with its validated CycloneDX 1.7 document (FR-004, FR-005)."""
    if store.get_model(model_id) is None:
        store.add_model(model_id, name=name, owner=owner)
    version = (store.latest_version(model_id) or 0) + 1
    document = export_bom(model_id, version, entries)
    validate(document)
    recorded = store.add_version(model_id, document, input_sha256, entries, base_dir=base_dir)
    if recorded != version:
        raise RuntimeError(f"expected to record version {version}, recorded {recorded}")
    return version


# --- checks and alerts (US2; the views are in reports.py, US5) ---------------------------------


def _check_text(payload: Mapping[str, Any]) -> str:
    lines = [f"Check run {payload['run_id']} ({payload['scope']})"]
    lines += [f"  {source}: {status}" for source, status in payload["sources"].items()]
    for model in payload["models"]:
        lines.append(
            f"{model['model_id']} v{model['version']}: {len(model['opened'])} opened,"
            f" {len(model['carried_forward'])} carried forward, {len(model['closed'])} closed,"
            f" {len(model['watch_events'])} watch events"
        )
    return "\n".join(lines)


def _alert_text(payload: Mapping[str, Any]) -> str:
    lines = [alert_line(payload).strip(), f"Model: {payload['model_id']}"]
    lines += [f"  {evidence_line(evidence)}" for evidence in payload["evidence"]]
    return "\n".join(lines)


def _route_dois(store: Store, fetcher: Fetcher, entries: Sequence[Mapping[str, Any]]) -> None:
    """Look up the registration agency of every dataset and tied paper DOI (research U1).

    A failed lookup is recorded with an empty agency and tried again later; it never fails the
    registration.
    """
    for entry in entries:
        if entry["kind"] != "dataset":
            continue
        dois = list(entry.get("paper_dois") or [])
        if entry["pinned"] and entry.get("hub_repo") is None:
            dois.insert(0, entry["identifier"])
        for doi in dois:
            ensure_agency(store, fetcher, doi)
            ensure_repository(store, fetcher, doi)


def make_handlers(
    fetcher: Fetcher | None = None, now: Callable[[], datetime] | None = None
) -> dict[str, Handler]:
    """The command handlers; ``fetcher`` and ``now`` stand in for sources and clock in tests."""

    def _open(path: Path | str) -> Store:
        return Store(path, now=now)

    def _fetcher() -> Fetcher:
        return UrlFetcher() if fetcher is None else fetcher

    def register(args: argparse.Namespace) -> CommandResult:
        try:
            manifest = load_manifest(args.manifest)
        except ManifestError as error:
            raise InvalidInputError(str(error)) from None
        model_id = args.model_id or manifest.model_id
        with _open(args.db) as store:
            if args.model_id is None and store.get_model(model_id) is not None:
                raise InvalidInputError(
                    f"model {model_id!r} is already registered; pass --model-id {model_id} to"
                    " register a new version"
                )
            fetcher_ = _fetcher()
            entries = build_entries(manifest, fetcher_)
            _route_dois(store, fetcher_, entries)
            record_licences(entries, fetcher_, store.get_routing)
            version = _record(
                store,
                model_id,
                entries,
                manifest.sha256,
                name=manifest.name,
                owner=manifest.owner,
                base_dir=Path(args.manifest).parent,
            )
            payload = _inventory_payload(model_id, version, store.entries(model_id, version))
            payload["alerts"] = reevaluate_version(store, model_id, version)
        return CommandResult(payload, _inventory_text(payload, f"Registered {model_id} v{version}"))

    def import_inventory(args: argparse.Namespace) -> CommandResult:
        try:
            raw = Path(args.bom).read_bytes()
            document = json.loads(raw)
        except (OSError, ValueError) as error:
            raise InvalidInputError(f"cannot read {args.bom} as JSON: {error}") from None
        try:
            entries = import_bom(document)
        except InventoryError as error:
            raise InvalidInputError(str(error)) from None
        model_id = args.model_id
        with _open(args.db) as store:
            version = _record(
                store,
                model_id,
                entries,
                hashlib.sha256(raw).hexdigest(),
                base_dir=Path(args.bom).parent,
            )
            payload = _inventory_payload(model_id, version, store.entries(model_id, version))
            payload["alerts"] = reevaluate_version(store, model_id, version)
        return CommandResult(payload, _inventory_text(payload, f"Imported {model_id} v{version}"))

    def show(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            version = _version_of(store, args.model_id, args.version)
            payload = _inventory_payload(
                args.model_id, version, store.entries(args.model_id, version)
            )
        return CommandResult(payload, _inventory_text(payload, f"{args.model_id} v{version}"))

    def export(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            version = _version_of(store, args.model_id, args.version)
            record = store.get_version(args.model_id, version)
        assert record is not None
        document = record["inventory"]
        validate(document)
        Path(args.output).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        payload = {"model_id": args.model_id, "version": version, "output": args.output}
        return CommandResult(payload, f"Wrote {args.model_id} v{version} to {args.output}")

    def check(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            if args.all:
                model_ids, scope = store.model_ids(), SCOPE_ALL
            else:
                _version_of(store, args.model_id, None)
                model_ids, scope = [args.model_id], args.model_id
            # contracts/cli.md: only ``check --all --scheduled`` is a scheduled run (FR-012).
            trigger = "scheduled" if args.all and args.scheduled else "on_demand"
            outcome = run_check(
                store, _fetcher(), model_ids, args.sources, scope=scope, trigger=trigger
            )
        payload = {
            "run_id": outcome.run_id,
            "scope": scope,
            "trigger": trigger,
            "sources": outcome.sources,
            "models": outcome.models,
        }
        return CommandResult(payload, _check_text(payload), sources_failed=outcome.failed)

    def policy(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            if store.get_model(args.model_id) is None:
                raise InvalidInputError(f"no model {args.model_id!r}")
            try:
                model = store.set_format_policy(args.model_id, args.format, set_by=args.by)
            except ValueError as error:
                raise InvalidInputError(str(error)) from None
        payload = {
            "model_id": args.model_id,
            "format_policy": model["format_policy"],
            "set_by": model["format_policy_set_by"],
            "set_at": model["format_policy_set_at"],
        }
        text = (
            f"{args.model_id}: format policy {payload['format_policy']}, set by"
            f" {payload['set_by']} at {payload['set_at']}; takes effect at the next check"
        )
        return CommandResult(payload, text)

    def alerts(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            _version_of(store, args.model_id, None)
            payload = alerts_report(store, args.model_id, state=args.state)
        return CommandResult(payload, alerts_text(payload))

    def history(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            _version_of(store, args.model_id, None)
            payload = history_report(store, args.model_id)
        return CommandResult(payload, history_text(payload))

    def alert_show(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            alert = store.get_alert(args.alert_id)
            if alert is None:
                raise InvalidInputError(f"no alert {args.alert_id}")
            payload = {"model_id": alert["model_id"], **alert_view(store, alert)}
        return CommandResult(payload, _alert_text(payload))

    def alert_dismiss(args: argparse.Namespace) -> CommandResult:
        with _open(args.db) as store:
            try:
                alert = dismiss_alert(
                    store, args.alert_id, reason=args.reason, by=args.by, note=args.note
                )
            except ValueError as error:
                raise InvalidInputError(str(error)) from None
            payload = {"model_id": alert["model_id"], **alert_view(store, alert)}
        text = (
            f"Dismissed alert {alert['alert_id']} ({alert['dismissal_reason']}) by"
            f" {alert['dismissed_by']} at {alert['closed_at']}"
        )
        return CommandResult(payload, text)

    return {
        "register": register,
        "import": import_inventory,
        "inventory show": show,
        "inventory export": export,
        "check": check,
        "policy": policy,
        "alerts": alerts,
        "alert show": alert_show,
        "alert dismiss": alert_dismiss,
        "history": history,
    }


DEFAULT_HANDLERS.update(make_handlers())


if __name__ == "__main__":
    sys.exit(main())
