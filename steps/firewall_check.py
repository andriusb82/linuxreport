from steps.base import ReportStep


class FirewallCheckStep(ReportStep):
    name = "Firewall check"

    def command(self) -> str:
        return r"""
sh -c '
echo "OS_RELEASE_BEGIN"
cat /etc/os-release 2>/dev/null
echo "OS_RELEASE_END"

echo "IPTABLES_INPUT_POLICY_BEGIN"
iptables -S INPUT 2>/dev/null
echo "IPTABLES_INPUT_POLICY_END"

echo "IP6TABLES_INPUT_POLICY_BEGIN"
ip6tables -S INPUT 2>/dev/null
echo "IP6TABLES_INPUT_POLICY_END"

echo "SS_LISTEN_BEGIN"
ss -lnt 2>/dev/null
echo "SS_LISTEN_END"

echo "UFW_STATUS_BEGIN"
ufw status 2>/dev/null
echo "UFW_STATUS_END"

echo "FIREWALLD_ACTIVE_BEGIN"
systemctl is-active firewalld 2>/dev/null || echo inactive
echo "FIREWALLD_ACTIVE_END"

echo "FIREWALLD_PORTS_BEGIN"
firewall-cmd --list-ports 2>/dev/null
echo "FIREWALLD_PORTS_END"

echo "FIREWALLD_SERVICES_BEGIN"
firewall-cmd --list-services 2>/dev/null
echo "FIREWALLD_SERVICES_END"

echo "FIREWALLD_IPV6_BEGIN"
firewall-cmd --get-log-denied 2>/dev/null
sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null
echo "FIREWALLD_IPV6_END"

echo "NFT_RULESET_BEGIN"
nft list ruleset 2>/dev/null
echo "NFT_RULESET_END"
'
"""

    def analyze(self, output: str) -> str:
        sections = self._parse_sections(output)

        distro = self._detect_distro(sections.get("OS_RELEASE_BEGIN", []))

        ufw_lines = sections.get("UFW_STATUS_BEGIN", [])
        firewalld_active_lines = sections.get("FIREWALLD_ACTIVE_BEGIN", [])
        firewalld_ports_lines = sections.get("FIREWALLD_PORTS_BEGIN", [])
        firewalld_services_lines = sections.get("FIREWALLD_SERVICES_BEGIN", [])
        iptables_input_lines = sections.get("IPTABLES_INPUT_POLICY_BEGIN", [])
        ip6tables_input_lines = sections.get("IP6TABLES_INPUT_POLICY_BEGIN", [])
        ss_lines = sections.get("SS_LISTEN_BEGIN", [])
        nft_lines = sections.get("NFT_RULESET_BEGIN", [])

        firewall_enabled = False
        ipv6_firewall_enabled = False
        incoming_ports = []
        drop_policy = False
        rules_found = False

        # UFW branch - typical for Ubuntu/Debian
        ufw_text = "\n".join(ufw_lines).strip()
        if ufw_text:
            if "Status: active" in ufw_text:
                firewall_enabled = True
                ipv6_firewall_enabled = "(v6)" in ufw_text or "Anywhere (v6)" in ufw_text
                incoming_ports.extend(self._parse_ufw_ports(ufw_lines))
                rules_found = len(incoming_ports) > 0

        # firewalld branch - typical for AlmaLinux / RHEL-like
        firewalld_active = any(line.strip() == "active" for line in firewalld_active_lines)
        if firewalld_active:
            firewall_enabled = True

            fw_ports = self._parse_firewalld_ports(firewalld_ports_lines)
            fw_services = self._parse_firewalld_services(firewalld_services_lines)

            incoming_ports.extend(fw_ports)
            incoming_ports.extend(fw_services)

            if fw_ports or fw_services:
                rules_found = True

            ipv6_firewall_enabled = True

        # Fallback to iptables / ip6tables / nftables
        input_policy_v4 = self._extract_iptables_policy(iptables_input_lines)
        input_policy_v6 = self._extract_iptables_policy(ip6tables_input_lines)

        if input_policy_v4 is not None:
            firewall_enabled = firewall_enabled or True
            if input_policy_v4 == "DROP":
                drop_policy = True

        if input_policy_v6 is not None:
            ipv6_firewall_enabled = True

        if nft_lines:
            nft_text = "\n".join(nft_lines)
            if "table" in nft_text and "chain" in nft_text:
                firewall_enabled = True
                if "hook input" in nft_text:
                    rules_found = True
                if "policy drop" in nft_text.lower():
                    drop_policy = True
                if "ip6" in nft_text.lower() or "ipv6" in nft_text.lower():
                    ipv6_firewall_enabled = True

        # If no explicit open incoming ports from firewall tool, fall back to listening sockets
        if not incoming_ports:
            incoming_ports = self._parse_listening_ports(ss_lines)

        if not drop_policy and not rules_found:
            if input_policy_v4 == "DROP":
                drop_policy = True

        incoming_ports = sorted(set(incoming_ports), key=self._port_sort_key)

        firewall_status_text = "enabled" if firewall_enabled else "not enabled"
        ipv6_status_text = "enabled" if ipv6_firewall_enabled else "not enabled"
        drop_text = "yes" if drop_policy else "no"

        ports_text = ", ".join(incoming_ports) if incoming_ports else "none detected"

        return (
            f"Firewall status: {firewall_status_text}. "
            f"Detected platform: {distro}. "
            f"Incoming open ports: {ports_text}. "
            f"Default drop policy on incoming traffic when no rule matches: {drop_text}. "
            f"IPv6 firewall: {ipv6_status_text}."
        )

    def _parse_sections(self, output: str) -> dict[str, list[str]]:
        markers = {
            "OS_RELEASE_BEGIN": "OS_RELEASE_END",
            "IPTABLES_INPUT_POLICY_BEGIN": "IPTABLES_INPUT_POLICY_END",
            "IP6TABLES_INPUT_POLICY_BEGIN": "IP6TABLES_INPUT_POLICY_END",
            "SS_LISTEN_BEGIN": "SS_LISTEN_END",
            "UFW_STATUS_BEGIN": "UFW_STATUS_END",
            "FIREWALLD_ACTIVE_BEGIN": "FIREWALLD_ACTIVE_END",
            "FIREWALLD_PORTS_BEGIN": "FIREWALLD_PORTS_END",
            "FIREWALLD_SERVICES_BEGIN": "FIREWALLD_SERVICES_END",
            "FIREWALLD_IPV6_BEGIN": "FIREWALLD_IPV6_END",
            "NFT_RULESET_BEGIN": "NFT_RULESET_END",
        }

        lines = output.splitlines()
        sections: dict[str, list[str]] = {}

        current = None
        for line in lines:
            stripped = line.strip()

            if stripped in markers:
                current = stripped
                sections[current] = []
                continue

            if current and stripped == markers[current]:
                current = None
                continue

            if current:
                sections[current].append(line.rstrip())

        return sections

    def _detect_distro(self, os_release_lines: list[str]) -> str:
        text = "\n".join(os_release_lines).lower()

        if "alma" in text:
            return "AlmaLinux"
        if "ubuntu" in text:
            return "Ubuntu"
        if "debian" in text:
            return "Debian"
        return "Unknown"

    def _parse_ufw_ports(self, lines: list[str]) -> list[str]:
        ports = []

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("Status:"):
                continue
            if line.startswith("To") and "Action" in line:
                continue
            if line.startswith("--"):
                continue

            parts = line.split()
            if not parts:
                continue

            target = parts[0]
            if target not in ports:
                ports.append(target)

        return ports

    def _parse_firewalld_ports(self, lines: list[str]) -> list[str]:
        ports = []
        for line in lines:
            for item in line.split():
                item = item.strip()
                if item:
                    ports.append(item)
        return ports

    def _parse_firewalld_services(self, lines: list[str]) -> list[str]:
        services = []
        for line in lines:
            for item in line.split():
                item = item.strip()
                if item:
                    services.append(f"service:{item}")
        return services

    def _extract_iptables_policy(self, lines: list[str]) -> str | None:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("-P INPUT "):
                return stripped.split()[-1]
        return None

    def _parse_listening_ports(self, lines: list[str]) -> list[str]:
        ports = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("State") or stripped.startswith("Recv-Q"):
                continue

            parts = stripped.split()
            if len(parts) < 4:
                continue

            local_address = parts[3]
            port = self._extract_port_from_address(local_address)
            if port:
                ports.append(port)

        return ports

    def _extract_port_from_address(self, address: str) -> str | None:
        address = address.strip()

        if not address:
            return None

        if address.startswith("[") and "]:" in address:
            return address.rsplit("]:", 1)[-1]

        if ":" in address:
            return address.rsplit(":", 1)[-1]

        return None

    def _port_sort_key(self, value: str):
        if value.startswith("service:"):
            return (1, value)

        port_part = value.split("/")[0]
        if port_part.isdigit():
            return (0, int(port_part))

        return (1, value) 