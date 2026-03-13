from steps.base import ReportStep


class RootkitCheckStep(ReportStep):
    name = "Rootkit scanner check"

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

echo "TOOL_DETECT_BEGIN"
if command -v rkhunter >/dev/null 2>&1; then
    echo "tool:rkhunter"
fi
if command -v chkrootkit >/dev/null 2>&1; then
    echo "tool:chkrootkit"
fi
echo "TOOL_DETECT_END"

TOOL=""
if command -v rkhunter >/dev/null 2>&1; then
    TOOL="rkhunter"
elif command -v chkrootkit >/dev/null 2>&1; then
    TOOL="chkrootkit"
fi

echo "PACKAGE_REFRESH_BEGIN"
if [ -n "$TOOL" ]; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/tmp/rootkit_pkg_refresh.out 2>/tmp/rootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/rootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/rootkit_pkg_refresh.err 2>/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf makecache >/tmp/rootkit_pkg_refresh.out 2>/tmp/rootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/rootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/rootkit_pkg_refresh.err 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum makecache >/tmp/rootkit_pkg_refresh.out 2>/tmp/rootkit_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/rootkit_pkg_refresh.out 2>/dev/null
        cat /tmp/rootkit_pkg_refresh.err 2>/dev/null
    else
        echo "exit_code:127"
        echo "No supported package manager found."
    fi
else
    echo "exit_code:0"
    echo "No scanner tool installed, package refresh skipped."
fi
echo "PACKAGE_REFRESH_END"

echo "TOOL_UPDATE_BEGIN"
if [ "$TOOL" = "rkhunter" ]; then
    rkhunter --update >/tmp/rootkit_tool_update.out 2>/tmp/rootkit_tool_update.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/rootkit_tool_update.out 2>/dev/null
    cat /tmp/rootkit_tool_update.err 2>/dev/null
elif [ "$TOOL" = "chkrootkit" ]; then
    echo "exit_code:0"
    echo "chkrootkit does not have a separate database update command."
elif [ -z "$TOOL" ]; then
    echo "exit_code:0"
    echo "No scanner tool installed, tool update skipped."
fi
echo "TOOL_UPDATE_END"

echo "SCAN_BEGIN"
if [ "$TOOL" = "rkhunter" ]; then
    rkhunter --check --skip-keypress >/tmp/rootkit_scan.out 2>/tmp/rootkit_scan.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/rootkit_scan.out 2>/dev/null
    cat /tmp/rootkit_scan.err 2>/dev/null
elif [ "$TOOL" = "chkrootkit" ]; then
    chkrootkit >/tmp/rootkit_scan.out 2>/tmp/rootkit_scan.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/rootkit_scan.out 2>/dev/null
    cat /tmp/rootkit_scan.err 2>/dev/null
else
    echo "exit_code:0"
    echo "No scanner tool installed, scan skipped."
fi
echo "SCAN_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))
        pkg_manager = self._first_nonempty(sections.get("PKG_MANAGER_BEGIN", [])) or "unknown"

        detected_tools = []
        for line in sections.get("TOOL_DETECT_BEGIN", []):
            stripped = line.strip()
            if stripped.startswith("tool:"):
                detected_tools.append(stripped.split(":", 1)[1])

        selected_tool = "none"
        if "rkhunter" in detected_tools:
            selected_tool = "rkhunter"
        elif "chkrootkit" in detected_tools:
            selected_tool = "chkrootkit"

        package_refresh_lines = sections.get("PACKAGE_REFRESH_BEGIN", [])
        tool_update_lines = sections.get("TOOL_UPDATE_BEGIN", [])
        scan_lines = sections.get("SCAN_BEGIN", [])

        package_refresh_rc = self._extract_exit_code(package_refresh_lines)
        tool_update_rc = self._extract_exit_code(tool_update_lines)
        scan_rc = self._extract_exit_code(scan_lines)

        package_refresh_status = self._status_text(package_refresh_rc)
        tool_update_status = self._status_text(tool_update_rc)
        scan_status = self._status_text(scan_rc)

        scan_summary = self._build_scan_summary(selected_tool, scan_lines)

        if not detected_tools:
            return (
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"Rootkit scanner tool check completed. Installed tool: none found. "
                f"Package metadata refresh: skipped. Tool update: skipped. Scan: skipped."
            )

        detected_tools_text = ", ".join(detected_tools)

        return (
            f"Detected platform: {distro}. Package manager: {pkg_manager}. "
            f"Installed rootkit scanner tools: {detected_tools_text}. "
            f"Selected tool: {selected_tool}. "
            f"Package metadata refresh: {package_refresh_status}. "
            f"Tool update: {tool_update_status}. "
            f"Scan execution: {scan_status}. "
            f"Scan result: {scan_summary}."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "OS_RELEASE_BEGIN": "OS_RELEASE_END",
            "PKG_MANAGER_BEGIN": "PKG_MANAGER_END",
            "TOOL_DETECT_BEGIN": "TOOL_DETECT_END",
            "PACKAGE_REFRESH_BEGIN": "PACKAGE_REFRESH_END",
            "TOOL_UPDATE_BEGIN": "TOOL_UPDATE_END",
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
                if value.isdigit():
                    return int(value)
        return None

    def _status_text(self, exit_code: int | None) -> str:
        if exit_code is None:
            return "unknown"
        if exit_code == 0:
            return "succeeded"
        return f"failed with exit code {exit_code}"

    def _build_scan_summary(self, selected_tool: str, scan_lines: list[str]) -> str:
        body_lines = []
        for line in scan_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("exit_code:"):
                continue
            body_lines.append(stripped)

        scan_text = " ".join(body_lines)

        if not scan_text:
            return "no scan output returned"

        if selected_tool == "rkhunter":
            warning_lines = [
                line.strip()
                for line in body_lines
                if "warning" in line.lower() or "infected" in line.lower() or "suspect" in line.lower()
            ]
            if warning_lines:
                return "warnings detected: " + "; ".join(warning_lines[:5])

            if "System checks summary" in scan_text or "Rootkit checks" in scan_text:
                return "scan completed and no obvious warnings were detected in summarized output"

            return self._truncate(scan_text, 300)

        if selected_tool == "chkrootkit":
            suspicious_lines = [
                line.strip()
                for line in body_lines
                if "infected" in line.lower()
                or "suspicious" in line.lower()
                or "warning" in line.lower()
            ]
            if suspicious_lines:
                return "findings detected: " + "; ".join(suspicious_lines[:5])

            clean_indicators = [
                line.strip()
                for line in body_lines
                if "not infected" in line.lower()
            ]
            if clean_indicators:
                return "scan completed; reported entries include 'not infected' results"

            return self._truncate(scan_text, 300)

        return self._truncate(scan_text, 300)

    def _truncate(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..." 