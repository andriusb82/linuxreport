from steps.base import ReportStep


class OpenPortsCheckStep(ReportStep):
    name = "Open ports check"

    # Extend this mapping in the future with more services and allowed ports
    SERVICE_PORTS = {
        "apache": {80, 443, 8080, 8443},
        "httpd": {80, 443, 8080, 8443},
        "nginx": {80, 443, 8080, 8443},
        "cpanel": {2082, 2083, 2086, 2087, 2095, 2096},
        "tomcat": {8005, 8009, 8080, 8443},
        "sshd": {22},
        "ssh": {22},
        "mysql": {3306},
        "mariadb": {3306},
        "postgres": {5432},
        "postmaster": {5432},
        "named": {53},
        "dnsmasq": {53},
        "bind": {53},
        "rpcbind": {111},
        "proxmox": {8006},
        "systemd-resolve":{53},
        "dovecot": {110, 143, 993, 995, 4190},
        "exim": {25, 465, 587},
        "postfix": {25, 465, 587},
        "master": {25, 465, 587},  # postfix master process
        "redis": {6379},
        "memcached": {11211},
        "vsftpd": {21},
        "proftpd": {21},
        "pure-ftpd": {21},
        "php-fpm": {9000},
        "php-fpm8.1": {9000},
        "php-fpm8.2": {9000},
        "php-fpm8.3": {9000},
        "docker-proxy": set(),  # intentionally flexible, often forwards many ports
    }

    def command(self) -> str:
        return r"""
sh -c '
echo "TOOL_BEGIN"
if command -v ss >/dev/null 2>&1; then
    echo "ss"
elif command -v netstat >/dev/null 2>&1; then
    echo "netstat"
else
    echo "none"
fi
echo "TOOL_END"

echo "PORTS_BEGIN"
if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
    netstat -tnlp 2>/dev/null
else
    echo "No supported socket inspection tool found."
fi
echo "PORTS_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        tool_lines = sections.get("TOOL_BEGIN", [])
        ports_lines = sections.get("PORTS_BEGIN", [])

        tool_used = self._first_nonempty(tool_lines) or "none"
        if tool_used == "none":
            return "Open ports check failed. Neither ss nor netstat is available."

        if tool_used == "ss":
            entries = self._parse_ss_output(ports_lines)
        else:
            entries = self._parse_netstat_output(ports_lines)

        if not entries:
            return f"Open ports check used {tool_used}. No listening TCP ports detected or output could not be parsed."

        mismatches = []
        formatted_entries = []

        unique_entries = []
        seen = set()
        for entry in entries:
            key = (entry["port"], entry["program"])
            if key in seen:
                continue
            seen.add(key)
            unique_entries.append(entry)

        unique_entries.sort(key=lambda item: (item["port"], item["program"]))

        for entry in unique_entries:
            port = entry["port"]
            program = entry["program"]
            normalized = self._normalize_program_name(program)

            formatted_entries.append(f"{port}/{program}")

            if normalized not in self.SERVICE_PORTS:
                mismatches.append(
                    f"port {port} is used by unrecognized service '{program}'"
                )
                continue

            allowed_ports = self.SERVICE_PORTS[normalized]

            # empty set means flexible service definition, do not flag
            if allowed_ports and port not in allowed_ports:
                allowed_text = ", ".join(str(item) for item in sorted(allowed_ports))
                mismatches.append(
                    f"service '{program}' is listening on port {port}, expected ports: {allowed_text}"
                )

        ports_text = ", ".join(formatted_entries)

        if mismatches:
            mismatch_text = "; ".join(mismatches)
            return (
                f"Open ports check used {tool_used}. "
                f"Listening TCP ports and programs: {ports_text}. "
                f"Mismatch detected: yes. {mismatch_text}."
            )

        return (
            f"Open ports check used {tool_used}. "
            f"Listening TCP ports and programs: {ports_text}. "
            f"Mismatch detected: no."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "TOOL_BEGIN": "TOOL_END",
            "PORTS_BEGIN": "PORTS_END",
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

    def _first_nonempty(self, lines: list[str]) -> str | None:
        for line in lines:
            stripped = line.strip()
            if stripped:
                return stripped
        return None

    def _parse_ss_output(self, lines: list[str]) -> list[dict[str, object]]:
        entries = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("State ") or line.startswith("Recv-Q "):
                continue
            if "LISTEN" not in line:
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            local_address = parts[3]
            process_part = parts[-1] if parts else ""
            port = self._extract_port(local_address)
            program = self._extract_program_from_ss(process_part)

            if port is None:
                continue

            entries.append(
                {
                    "port": port,
                    "program": program or "unknown",
                }
            )

        return entries

    def _parse_netstat_output(self, lines: list[str]) -> list[dict[str, object]]:
        entries = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("Active ") or line.startswith("Proto "):
                continue
            if "LISTEN" not in line:
                continue

            parts = line.split()
            if len(parts) < 7:
                continue

            local_address = parts[3]
            pid_program = parts[-1]
            port = self._extract_port(local_address)
            program = self._extract_program_from_netstat(pid_program)

            if port is None:
                continue

            entries.append(
                {
                    "port": port,
                    "program": program or "unknown",
                }
            )

        return entries

    def _extract_port(self, address: str) -> int | None:
        value = address.strip()

        if not value:
            return None

        if value.startswith("[") and "]:" in value:
            port_part = value.rsplit("]:", 1)[-1]
        else:
            port_part = value.rsplit(":", 1)[-1]

        if port_part.isdigit():
            return int(port_part)

        return None

    def _extract_program_from_ss(self, process_part: str) -> str:
        text = process_part.strip()
        if 'users:((' in text and '"' in text:
            try:
                return text.split('"')[1]
            except IndexError:
                return "unknown"
        return "unknown"

    def _extract_program_from_netstat(self, pid_program: str) -> str:
        value = pid_program.strip()

        if value == "-" or "/" not in value:
            return "unknown"

        return value.split("/", 1)[1]

    def _normalize_program_name(self, program: str) -> str:
        value = program.strip().lower()

        aliases = {
            "apache2": "apache",
            "httpd": "httpd",
            "nginx": "nginx",
            "sshd": "sshd",
            "mysqld": "mysql",
            "mariadbd": "mariadb",
            "postgres": "postgres",
            "postmaster": "postmaster",
            "named": "named",
            "dnsmasq": "dnsmasq",
            "dovecot": "dovecot",
            "exim": "exim",
            "master": "master",
            "redis-server": "redis",
            "memcached": "memcached",
            "vsftpd": "vsftpd",
            "proftpd": "proftpd",
            "pure-ftpd": "pure-ftpd",
            "php-fpm": "php-fpm",
            "docker-proxy": "docker-proxy",
            "cpsrvd": "cpanel",
            "cpanel": "cpanel",
            "java": "tomcat",  # best-effort for Tomcat when shown only as java
            "tomcat": "tomcat",
        }

        if value in aliases:
            return aliases[value]

        if value.startswith("php-fpm"):
            return value

        return value 