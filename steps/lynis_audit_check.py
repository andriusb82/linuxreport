from steps.base import ReportStep


class LynisAuditCheckStep(ReportStep):
    name = "Lynis audit check"

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

echo "LYNIS_DETECT_BEGIN"
if command -v lynis >/dev/null 2>&1; then
    echo "installed:yes"
    command -v lynis
    lynis --version 2>/dev/null || true
else
    echo "installed:no"
fi
echo "LYNIS_DETECT_END"

echo "PACKAGE_REFRESH_BEGIN"
if command -v lynis >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/tmp/lynis_pkg_refresh.out 2>/tmp/lynis_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/lynis_pkg_refresh.out 2>/dev/null
        cat /tmp/lynis_pkg_refresh.err 2>/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf makecache >/tmp/lynis_pkg_refresh.out 2>/tmp/lynis_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/lynis_pkg_refresh.out 2>/dev/null
        cat /tmp/lynis_pkg_refresh.err 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum makecache >/tmp/lynis_pkg_refresh.out 2>/tmp/lynis_pkg_refresh.err
        RC=$?
        echo "exit_code:$RC"
        cat /tmp/lynis_pkg_refresh.out 2>/dev/null
        cat /tmp/lynis_pkg_refresh.err 2>/dev/null
    else
        echo "exit_code:127"
        echo "No supported package manager found."
    fi
else
    echo "exit_code:0"
    echo "Lynis not installed, package refresh skipped."
fi
echo "PACKAGE_REFRESH_END"

echo "LYNIS_UPDATE_BEGIN"
if command -v lynis >/dev/null 2>&1; then
    lynis update info >/tmp/lynis_update.out 2>/tmp/lynis_update.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/lynis_update.out 2>/dev/null
    cat /tmp/lynis_update.err 2>/dev/null
else
    echo "exit_code:0"
    echo "Lynis not installed, update skipped."
fi
echo "LYNIS_UPDATE_END"

echo "LYNIS_AUDIT_BEGIN"
if command -v lynis >/dev/null 2>&1; then
    lynis audit system --quick --no-colors >/tmp/lynis_audit.out 2>/tmp/lynis_audit.err
    RC=$?
    echo "exit_code:$RC"
    cat /tmp/lynis_audit.out 2>/dev/null
    cat /tmp/lynis_audit.err 2>/dev/null
else
    echo "exit_code:0"
    echo "Lynis not installed, audit skipped."
fi
echo "LYNIS_AUDIT_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))
        pkg_manager = self._first_nonempty(sections.get("PKG_MANAGER_BEGIN", [])) or "unknown"

        detect_lines = sections.get("LYNIS_DETECT_BEGIN", [])
        refresh_lines = sections.get("PACKAGE_REFRESH_BEGIN", [])
        update_lines = sections.get("LYNIS_UPDATE_BEGIN", [])
        audit_lines = sections.get("LYNIS_AUDIT_BEGIN", [])

        lynis_installed = any(line.strip() == "installed:yes" for line in detect_lines)

        version = self._extract_version(detect_lines)
        refresh_status = self._status_text(self._extract_exit_code(refresh_lines))
        update_status = self._status_text(self._extract_exit_code(update_lines))
        audit_status = self._status_text(self._extract_exit_code(audit_lines))
        audit_summary = self._build_audit_summary(audit_lines)

        if not lynis_installed:
            return (
                f"Detected platform: {distro}. Package manager: {pkg_manager}. "
                f"Lynis installed: no. Package metadata refresh: skipped. "
                f"Lynis update: skipped. Lynis audit: skipped."
            )

        version_text = version if version else "unknown"

        return (
            f"Detected platform: {distro}. Package manager: {pkg_manager}. "
            f"Lynis installed: yes. Version: {version_text}. "
            f"Package metadata refresh: {refresh_status}. "
            f"Lynis update: {update_status}. "
            f"Lynis audit execution: {audit_status}. "
            f"Audit result: {audit_summary}."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "OS_RELEASE_BEGIN": "OS_RELEASE_END",
            "PKG_MANAGER_BEGIN": "PKG_MANAGER_END",
            "LYNIS_DETECT_BEGIN": "LYNIS_DETECT_END",
            "PACKAGE_REFRESH_BEGIN": "PACKAGE_REFRESH_END",
            "LYNIS_UPDATE_BEGIN": "LYNIS_UPDATE_END",
            "LYNIS_AUDIT_BEGIN": "LYNIS_AUDIT_END",
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

    def _extract_version(self, lines: list[str]) -> str | None:
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("installed:"):
                continue

            lower = stripped.lower()
            if "version" in lower:
                return stripped

            if stripped[0].isdigit():
                return stripped

        return None

    def _build_audit_summary(self, lines: list[str]) -> str:
        body_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("exit_code:"):
                continue
            body_lines.append(stripped)

        if not body_lines:
            return "no audit output returned"

        warnings = None
        suggestions = None
        hardening_index = None

        for line in body_lines:
            lower = line.lower()

            if lower.startswith("warnings") and ":" in line:
                warnings = line
            elif lower.startswith("suggestions") and ":" in line:
                suggestions = line
            elif "hardening index" in lower:
                hardening_index = line

        summary_parts = []
        if warnings:
            summary_parts.append(warnings)
        if suggestions:
            summary_parts.append(suggestions)
        if hardening_index:
            summary_parts.append(hardening_index)

        if summary_parts:
            return "; ".join(summary_parts)

        text = " ".join(body_lines)
        return self._truncate(text, 300)

    def _truncate(self, text: str, max_len: int) -> str:
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..." 