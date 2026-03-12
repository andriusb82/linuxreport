from __future__ import annotations

from models import StepResult
from steps.base import ReportStep
from connection import SSHConnectionManager


class Fail2BanCheckStep(ReportStep):
    name = "Fail2Ban status and monitored files"

    def command(self) -> str:
        return "command -v fail2ban-client >/dev/null 2>&1"

    def analyze(self, output: str) -> str:
        return output

    def run(self, connection: SSHConnectionManager) -> StepResult:
        _, _, exists_exit_code = connection.execute(self.command())
        if exists_exit_code != 0:
            conclusion = "Fail2Ban is not installed on this system."
            return StepResult(step_id=self.step_id, step_name=self.name, conclusion=conclusion)

        service_output, service_error, service_exit_code = connection.execute("systemctl is-active fail2ban")
        service_state = service_output.strip() if service_output.strip() else "unknown"
        is_working = service_exit_code == 0 and service_state == "active"

        if not is_working:
            detail = service_error.strip() or service_state or "unknown"
            conclusion = f"Fail2Ban is installed, but it is not working. Service state: {detail}."
            return StepResult(step_id=self.step_id, step_name=self.name, conclusion=conclusion)

        status_output, status_error, status_exit_code = connection.execute("fail2ban-client status")
        if status_exit_code != 0:
            detail = status_error.strip() or "unknown error"
            conclusion = (
                "Fail2Ban is installed and the service is active, but jail status could not be read. "
                f"Error: {detail}."
            )
            return StepResult(step_id=self.step_id, step_name=self.name, conclusion=conclusion)

        jail_names = self._parse_jails(status_output)
        if not jail_names:
            conclusion = "Fail2Ban is installed and working, but no jails are currently configured."
            return StepResult(step_id=self.step_id, step_name=self.name, conclusion=conclusion)

        monitored_parts: list[str] = []
        for jail_name in jail_names:
            log_output, _, log_exit_code = connection.execute(f"fail2ban-client get {jail_name} logpath")
            if log_exit_code == 0 and log_output.strip():
                logpaths = [line.strip() for line in log_output.splitlines() if line.strip()]
                monitored_parts.append(f"{jail_name}: {', '.join(logpaths)}")
            else:
                monitored_parts.append(f"{jail_name}: log paths unavailable")

        conclusion = (
            f"Fail2Ban is installed and working. Active jails: {', '.join(jail_names)}. "
            f"Monitored files: {'; '.join(monitored_parts)}."
        )
        return StepResult(step_id=self.step_id, step_name=self.name, conclusion=conclusion)

    @staticmethod
    def _parse_jails(status_output: str) -> list[str]:
        for line in status_output.splitlines():
            if "Jail list:" not in line:
                continue

            jail_part = line.split("Jail list:", 1)[1].strip()
            if not jail_part:
                return []

            return [jail.strip() for jail in jail_part.split(",") if jail.strip()]

        return []
