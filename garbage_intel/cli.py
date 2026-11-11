"""Command-line interface for the GARBAGE evidence ledger."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .store import (
    COLLECTION_BASES,
    MAX_ARCHIVE_BYTES,
    add_observation,
    backup_sqlite_database,
    build_timeline,
    build_report,
    create_json_backup,
    create_investigation,
    import_archive,
    initialize,
    list_investigations,
    set_investigation_status,
)
from .api import serve
from .modules.forensics import hash_file
from .modules.document_metadata import get_document_metadata
from .modules.cisa_kev import (
    cached_status,
    list_cached,
    refresh_cisa_kev,
)
from .reporting import render_csv_report, render_html_report
from .platform_support import runtime_diagnostics


def _database_default() -> str:
    return os.environ.get("GARBAGE_DATABASE", ".garbage/intelligence.sqlite3")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="garbage",
        description="Record and report sourced observations for investigations.",
    )
    parser.add_argument(
        "--database",
        default=_database_default(),
        help="SQLite database path (default: GARBAGE_DATABASE or %(default)s)",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="initialize the local intelligence database")
    commands.add_parser(
        "doctor", help="show Python and operating-system compatibility"
    )
    intelligence = commands.add_parser(
        "intel", help="read-only public intelligence connectors"
    )
    intelligence_commands = intelligence.add_subparsers(
        dest="intel_command", required=True
    )
    kev = intelligence_commands.add_parser(
        "kev", help="inspect CISA Known Exploited Vulnerabilities metadata"
    )
    kev_commands = kev.add_subparsers(dest="kev_command", required=True)
    refresh = kev_commands.add_parser(
        "refresh", help="manually refresh the CISA KEV cache over HTTPS"
    )
    refresh.add_argument(
        "--force",
        action="store_true",
        help="bypass the 15-minute cache interval; still performs only one request",
    )
    kev_commands.add_parser("status", help="show cached CISA KEV provenance")
    kev_list = kev_commands.add_parser("list", help="search cached CISA KEV metadata")
    kev_list.add_argument("--search", default="")
    kev_list.add_argument("--limit", type=int, default=25)
    backup = commands.add_parser(
        "backup", help="create a consistent, create-only SQLite database backup"
    )
    backup.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new backup path (must not already exist)",
    )
    backup.add_argument(
        "--format", choices=("json", "sqlite"), default="json"
    )
    restore = commands.add_parser(
        "import", help="validate and import a versioned JSON evidence archive"
    )
    restore.add_argument("--input", type=Path, required=True)

    investigation = commands.add_parser(
        "investigation", help="manage investigations"
    )
    investigation_commands = investigation.add_subparsers(
        dest="investigation_command", required=True
    )
    create = investigation_commands.add_parser("create", help="create an investigation")
    create.add_argument("--name", required=True)
    create.add_argument("--description", default="")
    investigation_commands.add_parser("list", help="list investigations")
    show = investigation_commands.add_parser("show", help="show an investigation report")
    show.add_argument("--investigation-id", required=True)
    timeline = investigation_commands.add_parser(
        "timeline", help="show an investigation's chronological events"
    )
    timeline.add_argument("--investigation-id", required=True)
    status = investigation_commands.add_parser(
        "set-status", help="open or close an investigation"
    )
    status.add_argument("--investigation-id", required=True)
    status.add_argument(
        "--status", choices=("open", "closed", "cancelled"), required=True
    )

    observation = commands.add_parser(
        "observation", help="record a sourced observation"
    )
    observation_commands = observation.add_subparsers(
        dest="observation_command", required=True
    )
    add = observation_commands.add_parser("add", help="add an observation")
    add.add_argument("--investigation-id", required=True)
    add.add_argument("--title", required=True)
    add.add_argument("--content", required=True)
    add.add_argument("--source-reference", required=True)
    add.add_argument(
        "--collection-basis",
        required=True,
        choices=COLLECTION_BASES,
        help="why this source may be used",
    )
    add.add_argument(
        "--observed-at",
        help="ISO 8601 observation time with timezone (defaults to now)",
    )

    report = commands.add_parser("report", help="render an investigation report")
    report.add_argument("--investigation-id", required=True)
    report.add_argument(
        "--format", choices=("json", "html", "csv"), default="json"
    )
    report.add_argument(
        "--output",
        type=Path,
        help="create a report file without overwriting an existing file",
    )

    server = commands.add_parser(
        "serve", help="run the local development API and web interface"
    )
    server.add_argument("--port", type=int, default=8000)

    forensics = commands.add_parser(
        "forensics", help="analyze one explicitly provided local file"
    )
    forensics_commands = forensics.add_subparsers(
        dest="forensics_command", required=True
    )
    hash_command = forensics_commands.add_parser(
        "hash-file", help="record a SHA-256 hash and metadata for a regular file"
    )
    hash_command.add_argument("--investigation-id", required=True)
    hash_command.add_argument("--path", required=True)
    metadata_command = forensics_commands.add_parser(
        "document-metadata",
        help="inspect metadata for one explicitly provided document",
    )
    metadata_command.add_argument("--path", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if (
            args.command == "forensics"
            and args.forensics_command == "document-metadata"
        ):
            result = get_document_metadata(args.path)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "doctor":
            result = runtime_diagnostics()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if all(
                item["supported"] for item in result.values()
            ) else 2
        if args.command == "backup":
            if args.format == "sqlite":
                result = backup_sqlite_database(args.database, args.output)
            else:
                result = create_json_backup(args.database, args.output)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "import":
            input_path = args.input
            if input_path.is_symlink() or not input_path.is_file():
                raise ValueError("archive input must be an existing regular file")
            with input_path.open("rb") as source:
                raw_archive = source.read(MAX_ARCHIVE_BYTES + 1)
            if len(raw_archive) > MAX_ARCHIVE_BYTES:
                raise ValueError("archive input exceeds the 10 MiB limit")
            try:
                archive = json.loads(raw_archive.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("archive input must be valid UTF-8 JSON") from exc
            result = import_archive(args.database, archive)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        initialize(args.database)
        if args.command == "init":
            result = {"database": args.database, "initialized": True}
        elif args.command == "investigation":
            if args.investigation_command == "create":
                result = create_investigation(
                    args.database, args.name, args.description
                )
            elif args.investigation_command == "list":
                result = list_investigations(args.database)
            elif args.investigation_command == "show":
                result = build_report(args.database, args.investigation_id)
            elif args.investigation_command == "timeline":
                result = build_timeline(args.database, args.investigation_id)
            else:
                result = set_investigation_status(
                    args.database, args.investigation_id, args.status
                )
        elif args.command == "observation":
            result = add_observation(
                args.database,
                args.investigation_id,
                args.title,
                args.content,
                args.source_reference,
                args.collection_basis,
                args.observed_at,
            )
        elif args.command == "intel":
            if args.intel_command == "kev":
                if args.kev_command == "refresh":
                    result = refresh_cisa_kev(args.database, force=args.force)
                elif args.kev_command == "status":
                    result = cached_status(args.database)
                else:
                    result = list_cached(
                        args.database, search=args.search, limit=args.limit
                    )
        elif args.command == "serve":
            if not 0 <= args.port <= 65535:
                raise ValueError("port must be between 0 and 65535")
            serve(args.database, args.port)
            return 0
        elif args.command == "forensics":
            analysis = hash_file(args.path)
            observation = add_observation(
                args.database,
                args.investigation_id,
                f"File hash: {analysis['file_name']}",
                (
                    f"SHA-256: {analysis['sha256']}\n"
                    f"Size bytes: {analysis['size_bytes']}\n"
                    f"Filesystem modified at: {analysis['modified_at']}"
                ),
                Path(analysis["path"]).as_uri(),
                "user-provided",
            )
            result = {"file_analysis": analysis, "observation": observation}
        elif args.command == "report":
            report = build_report(args.database, args.investigation_id)
            if args.format == "html":
                output = render_html_report(report)
            elif args.format == "csv":
                output = render_csv_report(report)
            else:
                output = json.dumps(report, ensure_ascii=False, indent=2)
            if args.output is not None:
                try:
                    with args.output.open(
                        "x", encoding="utf-8", newline=""
                    ) as destination:
                        destination.write(output)
                except FileExistsError as exc:
                    raise ValueError(
                        f"output already exists: {args.output}"
                    ) from exc
                print(
                    json.dumps(
                        {"format": args.format, "output": str(args.output)},
                        ensure_ascii=False,
                    )
                )
            else:
                sys.stdout.write(output)
                if not output.endswith("\n"):
                    sys.stdout.write("\n")
            return 0
        else:
            raise ValueError(f"unsupported command: {args.command}")
    except (OSError, ValueError) as exc:
        print(f"garbage: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
