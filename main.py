from __future__ import annotations

import argparse
from datetime import datetime
from typing import List

from connection import SSHConnectionError, SSHConnectionManager
from models import FinalReport, GeneralReportInfo
from report_builder import ReportFormatter
from step_registry import StepRegistry


def parse_selected_steps(selected: str) -> List[int]:
    result: List[int] = []
    for part in selected.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            raise argparse.ArgumentTypeError(f"Invalid step id: '{part}'")
        result.append(int(part))
    return result


def build_parser(registry: StepRegistry) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SSH Linux report tool",
        epilog=registry.help_text(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--host", required=True, help="SSH host or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--steps",
        type=parse_selected_steps,
        help="Comma-separated step ids to run, for example: --steps 1,3",
    )
    group.add_argument(
        "--from-step",
        type=int,
        help="Run all steps starting from this step number",
    )

    return parser


def filter_steps(all_steps, selected_steps: List[int] | None, from_step: int | None):
    if selected_steps:
        selected_set = set(selected_steps)
        return [step for step in all_steps if step.step_id in selected_set]

    if from_step is not None:
        return [step for step in all_steps if step.step_id >= from_step]

    return all_steps


def get_general_report_info(connection: SSHConnectionManager, target_host: str) -> GeneralReportInfo:
    hostname_out, _, _ = connection.execute("hostname")
    ip_out, _, _ = connection.execute("hostname -I")

    hostname = hostname_out.strip() or "unknown"
    ip_address = ip_out.split()[0] if ip_out.strip() else target_host

    return GeneralReportInfo(
        hostname=hostname,
        ip_address=ip_address,
        generated_at=datetime.now(),
    )


def main() -> int:
    registry = StepRegistry()
    parser = build_parser(registry)
    args = parser.parse_args()

    connection = SSHConnectionManager(
        host=args.host,
        port=args.port,
        username=args.user,
        password=args.password,
    )

    try:
        connection.connect()

        general_info = get_general_report_info(connection, args.host)
        all_steps = registry.build_all_steps()
        steps_to_run = filter_steps(all_steps, args.steps, args.from_step)

        if not steps_to_run:
            print("No steps selected to run.")
            return 1

        step_results = []
        for step in steps_to_run:
            print("running step")
            result = step.run(connection)
            step_results.append(result)

        final_report = FinalReport(
            general_info=general_info,
            step_results=step_results,
        )

        print(ReportFormatter.format(final_report))
        return 0

    except SSHConnectionError as exc:
        print(f"Connection error: {exc}")
        return 2
    except Exception as exc:
        print(f"Unexpected error: {exc}")
        return 3
    finally:
        connection.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())