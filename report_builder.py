from models import FinalReport


class ReportFormatter:
    @staticmethod
    def format(report: FinalReport) -> str:
        lines = [
            "===== SSH REPORT =====",
            f"Hostname: {report.general_info.hostname}",
            f"IP Address: {report.general_info.ip_address}",
            f"Report date: {report.general_info.generated_at.isoformat(sep=' ', timespec='seconds')}",
            "",
            "===== STEP RESULTS =====",
        ]

        for result in report.step_results:
            lines.extend(
                [
                    f"[{result.step_id}] {result.step_name}",
                    f"Conclusion: {result.conclusion}",
                    "",
                ]
            )

        return "\n".join(lines).rstrip()