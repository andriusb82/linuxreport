from steps.base import ReportStep


class VirusScanCheckStep(ReportStep):
    name = "Virus scan check"

    def command(self) -> str:
        return r"""
sh -c '
SESSION_NAME="clamav_scan_session"

if ! command -v screen >/dev/null 2>&1; then
    echo "SCREEN_BEGIN"
    echo "screen:not_installed"
    echo "SCREEN_END"
    exit 0
fi

echo "SCREEN_BEGIN"

if screen -list | grep -q "$SESSION_NAME"; then
    echo "screen:already_running"
    echo "SCREEN_END"
    exit 0
fi

echo "screen:starting_session"

screen -dmS "$SESSION_NAME" bash -c '"'"'

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

echo "CLAM_DETECT_BEGIN"
if command -v clamscan >/dev/null 2>&1; then
    echo "clamscan:yes"
    clamscan --version 2>/dev/null || true
else
    echo "clamscan:no"
fi

if command -v freshclam >/dev/null 2>&1; then
    echo "freshclam:yes"
else
    echo "freshclam:no"
fi
echo "CLAM_DETECT_END"

echo "PACKAGE_REFRESH_BEGIN"
if command -v clamscan >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/tmp/clam_pkg_refresh.out 2>/tmp/clam_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/clam_pkg_refresh.out 2>/dev/null
        cat /tmp/clam_pkg_refresh.err 2>/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf makecache >/tmp/clam_pkg_refresh.out 2>/tmp/clam_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/clam_pkg_refresh.out 2>/dev/null
        cat /tmp/clam_pkg_refresh.err 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum makecache >/tmp/clam_pkg_refresh.out 2>/tmp/clam_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/clam_pkg_refresh.out 2>/dev/null
        cat /tmp/clam_pkg_refresh.err 2>/dev/null
    else
        echo "exit_code:127"
        echo "No supported package manager found."
    fi
else
    echo "exit_code:0"
    echo "clamscan not installed, package refresh skipped."
fi
echo "PACKAGE_REFRESH_END"

echo "SIGNATURE_UPDATE_BEGIN"
if command -v freshclam >/dev/null 2>&1; then
    freshclam >/tmp/clam_update.out 2>/tmp/clam_update.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/clam_update.out 2>/dev/null
    cat /tmp/clam_update.err 2>/dev/null
elif command -v clamscan >/dev/null 2>&1; then
    echo "exit_code:0"
    echo "freshclam not available, signature update skipped."
else
    echo "exit_code:0"
    echo "clamscan not installed, signature update skipped."
fi
echo "SIGNATURE_UPDATE_END"

echo "SCAN_BEGIN"
if command -v clamscan >/dev/null 2>&1; then
    clamscan -r / --infected --max-filesize=100M --max-scansize=500M \
        --exclude-dir="^/sys" \
        --exclude-dir="^/proc" \
        --exclude-dir="^/dev" \
        --exclude-dir="^/run" \
        --exclude-dir="^/tmp" \
        >/tmp/clam_scan.out 2>/tmp/clam_scan.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/clam_scan.out 2>/dev/null
    cat /tmp/clam_scan.err 2>/dev/null
else
    echo "exit_code:0"
    echo "clamscan not installed, scan skipped."
fi
echo "SCAN_END"

'"'"' > /tmp/clamav_screen_scan.log 2>&1

echo "screen:started"
echo "SCREEN_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))
        pkg_manager = self._first_nonempty(sections.get("PKG_MANAGER_BEGIN", [])) or "unknown"

        detect_lines = sections.get("CLAM_DETECT_BEGIN", [])
        refresh_lines = sections.get("PACKAGE_REFRESH_BEGIN", [])
        update_lines = sections.get("SIGNATURE_UPDATE_BEGIN", [])
        scan_lines = sections.get("SCAN_BEGIN", [])

        clamscan_installed = any(line.strip() == "clamscan:yes" for line in detect_lines)
        freshclam_installed = any(line.strip() == "freshclam:yes" for line in detect_lines)

        version = self._extract_version(detect_lines)
        refresh_status = self._status_text(self._extract_exit_code(refresh_lines))
        update_status = self._status_text(self._extract_exit_code(update_lines))
        scan_exit_code = self._extract_exit_code(scan_lines)
        scan_status = self._scan_status_text(scan_exit_code)
        scan_summary = self._build_scan_summary(scan_lines)

        if not clamscan_installed:
            return (
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"ClamAV installed: no. Package metadata refresh: skipped. "
                f"Signature update: skipped. Filesystem scan: skipped."
            )

        freshclam_text = "yes" if freshclam_installed else "no"
        version_text = version if version else "unknown"

        return (
            f"Detected platform: {distro}. Package manager: {pkg_manager}. "
            f"ClamAV installed: yes. Version: {version_text}. "
            f"freshclam available: {freshclam_text}. "
            f"Package metadata refresh: {refresh_status}. "
            f"Signature update: {update_status}. "
            f"Filesystem scan: {scan_status}. "
            f"Scan result: {scan_summary}."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "OS_RELEASE_BEGIN": "OS_RELEASE_END",
            "PKG_MANAGER_BEGIN": "PKG_MANAGER_END",
            "CLAM_DETECT_BEGIN": "CLAM_DETECT_END",
            "PACKAGE_REFRESH_BEGIN": "PACKAGE_REFRESH_END",
            "SIGNATURE_UPDATE_BEGIN": "SIGNATURE_UPDATE_END",
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

    def _scan_status_text(self, exit_code: int | None) -> str:
        if exit_code is None:
            return "unknown"
        if exit_code == 0:
            return "completed with no infected files found"
        if exit_code == 1:
            return "completed and infected files were found"
        return f"failed with exit code {exit_code}"

    def _extract_version(self, lines: list[str]) -> str | None:
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("clamscan:") or stripped.startswith("freshclam:"):
                continue
            if "ClamAV" in stripped or stripped[0].isdigit():
                return stripped
        return None

    def _build_scan_summary(self, lines: list[str]) -> str:
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("exit_code:"):
                continue
            body_lines.append(stripped)

        if not body_lines:
            return "no scan output returned"

        scanned_files = None
        infected_files = None
        scanned_dirs = None

        for line in body_lines:
            lower = line.lower()
            if lower.startswith("scanned files:"):
                scanned_files = line
            elif lower.startswith("scanned directories:"):
                scanned_dirs = line
            elif lower.startswith("infected files:"):
                infected_files = line

        summary_parts = []
        if scanned_files:
            summary_parts.append(scanned_files)
        if scanned_dirs:
            summary_parts.append(scanned_dirs)
        if infected_files:
            summary_parts.append(infected_files)

        if summary_parts:
            return "; ".join(summary_parts)

        findings = [
            line for line in body_lines
            if "found" in line.lower() or "infected" in line.lower()
        ]
        if findings:
            return "; ".join(findings[:5])

        text = " ".join(body_lines)
        return self._truncate(text, 300)

    def _truncate(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..." 