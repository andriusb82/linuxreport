from steps.base import ReportStep


class VirusScanCheckStep(ReportStep):
    name = "Virus scan check"

    def command(self) -> str:
        return r"""
sh -c '
SESSION_NAME="clamav_scan_session"
STATE_DIR="/tmp/clamav_scan_state"
STATUS_FILE="$STATE_DIR/status"
RESULTS_FILE="$STATE_DIR/results.log"
PROGRESS_FILE="$STATE_DIR/progress.log"

mkdir -p "$STATE_DIR"

echo "SCREEN_BEGIN"

if ! command -v screen >/dev/null 2>&1; then
    echo "screen:not_installed"
    echo "SCREEN_END"
    exit 0
fi

if screen -list | grep -q "[[:space:]]${SESSION_NAME}[[:space:]]"; then
    echo "screen:already_running"
else
    rm -f "$STATUS_FILE" "$RESULTS_FILE" "$PROGRESS_FILE"

    cat > "$STATE_DIR/run_scan.sh" <<'"'"'EOS'"'"'
#!/usr/bin/env bash
set +e

STATE_DIR="/tmp/clamav_scan_state"
STATUS_FILE="$STATE_DIR/status"
RESULTS_FILE="$STATE_DIR/results.log"
PROGRESS_FILE="$STATE_DIR/progress.log"

mkdir -p "$STATE_DIR"
: > "$RESULTS_FILE"
: > "$PROGRESS_FILE"

exec > >(tee -a "$PROGRESS_FILE") 2>&1

write_result() {
    printf "%s\n" "$1" >> "$RESULTS_FILE"
}

run_and_capture() {
    section_name="$1"
    shift

    write_result "${section_name}_BEGIN"
    "$@" >"$STATE_DIR/${section_name}.out" 2>"$STATE_DIR/${section_name}.err"
    rc=$?
    write_result "exit_code:$rc"
    cat "$STATE_DIR/${section_name}.out" >> "$RESULTS_FILE" 2>/dev/null || true
    cat "$STATE_DIR/${section_name}.err" >> "$RESULTS_FILE" 2>/dev/null || true
    write_result "${section_name}_END"
    return 0
}

echo "status:running" > "$STATUS_FILE"

write_result "OS_RELEASE_BEGIN"
cat /etc/os-release 2>/dev/null >> "$RESULTS_FILE"
write_result "OS_RELEASE_END"

write_result "PKG_MANAGER_BEGIN"
if command -v apt-get >/dev/null 2>&1; then
    echo "apt" >> "$RESULTS_FILE"
    PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
    echo "dnf" >> "$RESULTS_FILE"
    PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
    echo "yum" >> "$RESULTS_FILE"
    PKG_MANAGER="yum"
else
    echo "unknown" >> "$RESULTS_FILE"
    PKG_MANAGER="unknown"
fi
write_result "PKG_MANAGER_END"

write_result "CLAM_DETECT_BEGIN"
if command -v clamscan >/dev/null 2>&1; then
    write_result "clamscan:yes"
    clamscan --version 2>/dev/null | head -n 1 >> "$RESULTS_FILE" || true
    HAS_CLAMSCAN=1
else
    write_result "clamscan:no"
    HAS_CLAMSCAN=0
fi

if command -v freshclam >/dev/null 2>&1; then
    write_result "freshclam:yes"
    HAS_FRESHCLAM=1
else
    write_result "freshclam:no"
    HAS_FRESHCLAM=0
fi
write_result "CLAM_DETECT_END"

write_result "PACKAGE_REFRESH_BEGIN"
if [ "$HAS_CLAMSCAN" -eq 1 ]; then
    if [ "$PKG_MANAGER" = "apt" ]; then
        apt-get update >"$STATE_DIR/PACKAGE_REFRESH.out" 2>"$STATE_DIR/PACKAGE_REFRESH.err"
        rc=$?
    elif [ "$PKG_MANAGER" = "dnf" ]; then
        dnf makecache >"$STATE_DIR/PACKAGE_REFRESH.out" 2>"$STATE_DIR/PACKAGE_REFRESH.err"
        rc=$?
    elif [ "$PKG_MANAGER" = "yum" ]; then
        yum makecache >"$STATE_DIR/PACKAGE_REFRESH.out" 2>"$STATE_DIR/PACKAGE_REFRESH.err"
        rc=$?
    else
        echo "No supported package manager found." >"$STATE_DIR/PACKAGE_REFRESH.err"
        : >"$STATE_DIR/PACKAGE_REFRESH.out"
        rc=127
    fi
    write_result "exit_code:$rc"
    cat "$STATE_DIR/PACKAGE_REFRESH.out" >> "$RESULTS_FILE" 2>/dev/null || true
    cat "$STATE_DIR/PACKAGE_REFRESH.err" >> "$RESULTS_FILE" 2>/dev/null || true
else
    write_result "exit_code:0"
    write_result "clamscan not installed, package refresh skipped."
fi
write_result "PACKAGE_REFRESH_END"

write_result "SIGNATURE_UPDATE_BEGIN"
if [ "$HAS_FRESHCLAM" -eq 1 ]; then
    freshclam >"$STATE_DIR/SIGNATURE_UPDATE.out" 2>"$STATE_DIR/SIGNATURE_UPDATE.err"
    rc=$?
    write_result "exit_code:$rc"
    cat "$STATE_DIR/SIGNATURE_UPDATE.out" >> "$RESULTS_FILE" 2>/dev/null || true
    cat "$STATE_DIR/SIGNATURE_UPDATE.err" >> "$RESULTS_FILE" 2>/dev/null || true
elif [ "$HAS_CLAMSCAN" -eq 1 ]; then
    write_result "exit_code:0"
    write_result "freshclam not available, signature update skipped."
else
    write_result "exit_code:0"
    write_result "clamscan not installed, signature update skipped."
fi
write_result "SIGNATURE_UPDATE_END"

write_result "SCAN_BEGIN"
if [ "$HAS_CLAMSCAN" -eq 1 ]; then
    clamscan -r / --infected --max-filesize=100M --max-scansize=500M \
        --exclude-dir="^/sys" \
        --exclude-dir="^/proc" \
        --exclude-dir="^/dev" \
        --exclude-dir="^/run" \
        --exclude-dir="^/tmp" \
        2>&1 | tee "$STATE_DIR/clamscan_live.out"
    rc=${PIPESTATUS[0]}
    write_result "exit_code:$rc"
    cat "$STATE_DIR/clamscan_live.out" >> "$RESULTS_FILE" 2>/dev/null || true
else
    write_result "exit_code:0"
    write_result "clamscan not installed, scan skipped."
fi
write_result "SCAN_END"

echo "status:finished" > "$STATUS_FILE"
EOS

    chmod +x "$STATE_DIR/run_scan.sh"
    screen -dmS "$SESSION_NAME" bash "$STATE_DIR/run_scan.sh"
    echo "screen:started"
fi

if [ -f "$STATUS_FILE" ]; then
    cat "$STATUS_FILE"
else
    echo "status:not_started"
fi

if [ -f "$RESULTS_FILE" ]; then
    cat "$RESULTS_FILE"
fi

echo "SCREEN_END"
'
"""

    def analyze(self, output: str) -> str:
        screen_lines = self._extract_screen_lines(output)
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))
        pkg_manager = self._first_nonempty(sections.get("PKG_MANAGER_BEGIN", [])) or "unknown"

        screen_status = self._find_prefixed_value(screen_lines, "screen:")
        run_status = self._find_prefixed_value(screen_lines, "status:")

        detect_lines = sections.get("CLAM_DETECT_BEGIN", [])
        refresh_lines = sections.get("PACKAGE_REFRESH_BEGIN", [])
        update_lines = sections.get("SIGNATURE_UPDATE_BEGIN", [])
        scan_lines = sections.get("SCAN_BEGIN", [])

        clamscan_installed = any(line.strip() == "clamscan:yes" for line in detect_lines)
        freshclam_installed = any(line.strip() == "freshclam:yes" for line in detect_lines)

        if screen_status == "not_installed":
            return "screen is not installed on target host, so detached antivirus scan could not be started."

        if run_status == "not_started" and screen_status not in {"started", "already_running"}:
            return "Antivirus scan was not started and no saved status information was found."

        if run_status == "running":
            return (
                f"Virus scan screen session is currently running. "
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"ClamAV installed: {'yes' if clamscan_installed else 'no'}. "
                f"freshclam available: {'yes' if freshclam_installed else 'no'}. "
                f"You can attach with: screen -r clamav_scan_session."
            )

        if not clamscan_installed:
            return (
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"ClamAV installed: no. Package metadata refresh: skipped. "
                f"Signature update: skipped. Filesystem scan: skipped."
            )

        version = self._extract_version(detect_lines)
        refresh_status = self._status_text(self._extract_exit_code(refresh_lines))
        update_status = self._status_text(self._extract_exit_code(update_lines))
        scan_exit_code = self._extract_exit_code(scan_lines)
        scan_status = self._scan_status_text(scan_exit_code)
        scan_summary = self._build_scan_summary(scan_lines)

        return (
            f"Detected platform: {distro}. Package manager: {pkg_manager}. "
            f"ClamAV installed: yes. Version: {version or 'unknown'}. "
            f"freshclam available: {'yes' if freshclam_installed else 'no'}. "
            f"Package metadata refresh: {refresh_status}. "
            f"Signature update: {update_status}. "
            f"Filesystem scan: {scan_status}. "
            f"Scan result: {scan_summary}."
        )

    def _extract_screen_lines(self, output: str) -> list[str]:
        lines = []
        in_screen = False
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line == "SCREEN_BEGIN":
                in_screen = True
                continue
            if line == "SCREEN_END":
                in_screen = False
                continue
            if in_screen:
                lines.append(line)
        return lines

    def _find_prefixed_value(self, lines: list[str], prefix: str) -> str | None:
        for line in lines:
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
        return None

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