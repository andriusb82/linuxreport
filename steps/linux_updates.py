from __future__ import annotations

from connection import SSHConnectionManager
from models import StepResult
from steps.base import ReportStep


class LinuxUpdatesStep(ReportStep):
    name = "Linux updates"

    def command(self) -> str:
        return "true"

    def analyze(self, output: str) -> str:
        return output.strip() or "Linux update step finished."

    def run(self, connection: SSHConnectionManager) -> StepResult:
        distro_family = self._detect_distro_family(connection)

        if distro_family == "debian":
            conclusion = self._run_debian_flow(connection)
        elif distro_family == "alma":
            conclusion = self._run_alma_flow(connection)
        else:
            conclusion = (
                "Linux update step could not continue. "
                "Supported distributions are AlmaLinux, Debian, and Ubuntu. "
                f"Detected distribution family: {distro_family}."
            )

        return StepResult(
            step_id=self.step_id,
            step_name=self.name,
            conclusion=conclusion,
        )

    def _detect_distro_family(self, connection: SSHConnectionManager) -> str:
        command = (
            "sh -c '. /etc/os-release 2>/dev/null; "
            "printf \"%s|%s\" \"${ID:-unknown}\" \"${ID_LIKE:-}\"'"
        )
        output, error, exit_code = connection.execute(command)

        if exit_code != 0:
            return f"unknown ({self._clean_text(error or output or 'could not read /etc/os-release')})"

        os_id, _, os_like = output.lower().partition("|")
        normalized = f"{os_id} {os_like}".strip()

        if "ubuntu" in normalized or "debian" in normalized:
            return "debian"

        if any(name in normalized for name in ("almalinux", "alma", "rhel", "centos", "rocky", "fedora")):
            return "alma"

        return normalized or "unknown"

    def _run_debian_flow(self, connection: SSHConnectionManager) -> str:
        parts = ["Detected distribution: Debian/Ubuntu."]

        check_out, check_err, check_rc = connection.execute(
            "DEBIAN_FRONTEND=noninteractive apt-get update"
        )
        if check_rc != 0:
            parts.append(
                f"Update check failed with exit code {check_rc}. "
                f"Details: {self._clean_text(check_err or check_out)}."
            )
        else:
            list_out, list_err, list_rc = connection.execute(
                "sh -c 'apt list --upgradable 2>/dev/null | tail -n +2'"
            )
            if list_rc != 0:
                parts.append(
                    "Update check completed, but the number of pending package updates "
                    f"could not be determined. Details: {self._clean_text(list_err or list_out)}."
                )
            else:
                packages = [line for line in list_out.splitlines() if line.strip()]
                parts.append(f"Pending package updates before installation: {len(packages)}.")

        update_out, update_err, update_rc = connection.execute(
            "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
        )
        if update_rc != 0:
            parts.append(
                f"Update installation failed with exit code {update_rc}. "
                f"Details: {self._clean_text(update_err or update_out)}."
            )
        else:
            parts.append("Update installation finished without command error.")

        reboot_out, reboot_err, reboot_rc = connection.execute(
            "sh -c 'if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi'"
        )
        if reboot_rc != 0:
            parts.append(
                "Restart requirement could not be determined. "
                f"Details: {self._clean_text(reboot_err or reboot_out)}."
            )
        else:
            reboot_required = reboot_out.strip().lower() == "yes"
            parts.append(f"Computer restart required: {'yes' if reboot_required else 'no'}.")

        return " ".join(parts)

    def _run_alma_flow(self, connection: SSHConnectionManager) -> str:
        parts = ["Detected distribution: AlmaLinux/RHEL family."]

        check_out, check_err, check_rc = connection.execute("dnf check-update")
        if check_rc == 0:
            parts.append("No pending package updates were reported before installation.")
        elif check_rc == 100:
            package_lines = self._extract_dnf_package_lines(check_out)
            if package_lines:
                parts.append(f"Pending package updates before installation: {len(package_lines)}.")
            else:
                parts.append("Pending package updates were reported before installation.")
        else:
            parts.append(
                f"Update check failed with exit code {check_rc}. "
                f"Details: {self._clean_text(check_err or check_out)}."
            )

        update_out, update_err, update_rc = connection.execute("dnf upgrade -y")
        if update_rc != 0:
            parts.append(
                f"Update installation failed with exit code {update_rc}. "
                f"Details: {self._clean_text(update_err or update_out)}."
            )
        else:
            parts.append("Update installation finished without command error.")

        reboot_command = (
            "sh -c '"
            "if command -v needs-restarting >/dev/null 2>&1; then "
            "needs-restarting -r >/dev/null 2>&1; rc=$?; "
            "if [ \"$rc\" -eq 0 ]; then echo no; "
            "elif [ \"$rc\" -eq 1 ]; then echo yes; "
            "else echo unknown; fi; "
            "else echo unknown; fi'"
        )
        reboot_out, reboot_err, reboot_rc = connection.execute(reboot_command)
        if reboot_rc != 0:
            parts.append(
                "Restart requirement could not be determined. "
                f"Details: {self._clean_text(reboot_err or reboot_out)}."
            )
        else:
            reboot_value = reboot_out.strip().lower()
            if reboot_value == "yes":
                parts.append("Computer restart required: yes.")
            elif reboot_value == "no":
                parts.append("Computer restart required: no.")
            else:
                parts.append(
                    "Computer restart requirement is unknown. "
                    "The 'needs-restarting' utility is unavailable or returned an inconclusive result."
                )

        return " ".join(parts)

    def _extract_dnf_package_lines(self, output: str) -> list[str]:
        package_lines: list[str] = []

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("Last metadata expiration check:", "Obsoleting Packages")):
                continue
            if stripped.startswith(("Security:", "Update", "Available", "Installed")):
                continue
            columns = stripped.split()
            if len(columns) >= 3:
                package_lines.append(stripped)

        return package_lines

    @staticmethod
    def _clean_text(value: str) -> str:
        cleaned = " ".join(part.strip() for part in value.splitlines() if part.strip())
        if not cleaned:
            return "no details returned"
        if len(cleaned) > 300:
            return cleaned[:297] + "..."
        return cleaned
