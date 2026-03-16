from steps.base import ReportStep


class ChkrootkitCheckStep(ReportStep):
    name = "chkrootkit scanner check"

    def command(self) -> str:
        return r"""
sh -c '
echo "OS_RELEASE_BEGIN"
cat /etc/os-release 2>/dev/null
echo "OS_RELEASE_END"

echo "PKG_MANAGER_BEGIN"
if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
elif command -v yum >/dev/null 2>&1; then
    echo "yum"
else
    echo "unknown"
fi
echo "PKG_MANAGER_END"

echo "CHKROOTKIT_DETECT_BEGIN"
if command -v chkrootkit >/dev/null 2>&1; then
    echo "installed:yes"
    command -v chkrootkit
else
    echo "installed:no"
fi
echo "CHKROOTKIT_DETECT_END"

echo "PACKAGE_REFRESH_BEGIN"
if command -v chkrootkit >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/tmp/chkrootkit_pkg_refresh.out 2>/tmp/chkrootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/chkrootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/chkrootkit_pkg_refresh.err 2>/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf makecache >/tmp/chkrootkit_pkg_refresh.out 2>/tmp/chkrootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/chkrootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/chkrootkit_pkg_refresh.err 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum makecache >/tmp/chkrootkit_pkg_refresh.out 2>/tmp/chkrootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/chkrootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/chkrootkit_pkg_refresh.err 2>/dev/null
    else
        echo "exit_code:127"
        echo "No supported package manager found."
    fi
else
    echo "exit_code:0"
    echo "chkrootkit not installed, package refresh skipped."
fi
echo "PACKAGE_REFRESH_END"

echo "CHKROOTKIT_UPDATE_BEGIN"
if command -v chkrootkit >/dev/null 2>&1; then
    echo "exit_code:0"
    echo "chkrootkit does not have a separate database update command."
else
    echo "exit_code:0"
    echo "chkrootkit not installed, update skipped."
fi
echo "CHKROOTKIT_UPDATE_END"

echo "SCAN_BEGIN"
if command -v chkrootkit >/dev/null 2>&1; then
    chkrootkit >/tmp/chkrootkit_scan.out 2>/tmp/chkrootkit_scan.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/chkrootkit_scan.out 2>/dev/null
    cat /tmp/chkrootkit_scan.err 2>/dev/null
else
    echo "exit_code:0"
    echo "chkrootkit not installed, scan skipped."
fi
echo "SCAN_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))
        pkg_manager = self._first_nonempty(sections.get("PKG_MANAGER_BEGIN", [])) or "unknown"

        detect_lines = sections.get("CHKROOTKIT_DETECT_BEGIN", [])
        refresh_lines = sections.get("PACKAGE_REFRESH_BEGIN", [])
        update_lines = sections.get("CHKROOTKIT_UPDATE_BEGIN", [])
        scan_lines = sections.get("SCAN_BEGIN", [])

        chkrootkit_installed = any(line.strip() == "installed:yes" for line in detect_lines)

        refresh_status = self._status_text(self._extract_exit_code(refresh_lines))
        update_status = self._status_text(self._extract_exit_code(update_lines))
        scan_status = self._status_text(self._extract_exit_code(scan_lines))
        scan_summary = self._build_scan_summary(scan_lines)

        if not chkrootkit_installed:
            return (
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"chkrootkit installed: no. Package metadata refresh: skipped. "
                f"Tool update: skipped. Scan: skipped."
            )

        return (
            f"Detected platform: {distro}. Package manager: {pkg_manager}. "
            f"chkrootkit installed: yes. "
            f"Package metadata refresh: {refresh_status}. "
            f"Tool update: {update_status}. "
            f"Scan execution: {scan_status}. "
            f"Scan result: {scan_summary}."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "OS_RELEASE_BEGIN": "OS_RELEASE_END",
            "PKG_MANAGER_BEGIN": "PKG_MANAGER_END",
            "CHKROOTKIT_DETECT_BEGIN": "CHKROOTKIT_DETECT_END",
            "PACKAGE_REFRESH_BEGIN": "PACKAGE_REFRESH_END",
            "CHKROOTKIT_UPDATE_BEGIN": "CHKROOTKIT_UPDATE_END",
            "SCAN_BEGIN": "SCAN_END",
        }

        sections: dict[str, list[str]] = {}
        current = None

        for line in output.splitlines():
            stripped = line.strip()

            if stripped in markers:
                current = stripped
                sections[current] = []
                continue

            if current and stripped == markers[current]:
                current = None
                continue

            if current is not None:
                sections[current].append(line.rstrip())

        return sections

    def _detect_distro(self, os_release_lines: list[str]) -> str:
        text = "\n".join(os_release_lines).lower()
        if "almalinux" in text or "alma" in text:
            return "AlmaLinux"
        if "ubuntu" in text:
            return "Ubuntu"
        if "debian" in text:
            return "Debian"
        return "Unknown"

    def _first_nonempty(self, lines: list[str]) -> str | None:
        for line in lines:
            stripped = line.strip()
            if stripped:
                return stripped
        return None

    def _extract_exit_code(self, lines: list[str]) -> int | None:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("exit_code:"):
                value = stripped.split(":", 1)[1].strip()
                if value.lstrip("-").isdigit():
                    return int(value)
        return None

    def _status_text(self, exit_code: int | None) -> str:
        if exit_code is None:
            return "unknown"
        if exit_code == 0:
            return "succeeded"
        return f"failed with exit code {exit_code}"

    def _build_scan_summary(self, scan_lines: list[str]) -> str:
        body_lines = []
        for line in scan_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("exit_code:"):
                continue
            body_lines.append(stripped)

        if not body_lines:
            return "no scan output returned"

        suspicious_lines = [
            line for line in body_lines
            if "infected" in line.lower()
            or "suspicious" in line.lower()
            or "warning" in line.lower()
        ]
        if suspicious_lines:
            return "findings detected: " + "; ".join(suspicious_lines[:5])

        clean_lines = [
            line for line in body_lines
            if "not infected" in line.lower()
        ]
        if clean_lines:
            return "scan completed; reported entries include 'not infected' results"

        return self._truncate(" ".join(body_lines), 300)

    def _truncate(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."