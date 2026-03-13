from steps.base import ReportStep


class LoginUsersCheckStep(ReportStep):
    name = "Users that can log in"

    NON_LOGIN_SHELLS = {
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/nologin",
        "/usr/bin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "nologin",
        "false",
    }

    def command(self) -> str:
        return r"""
sh -c '
cat /etc/passwd 2>/dev/null
'
"""

    def analyze(self, output: str) -> str:
        if not output.strip():
            return "Could not read /etc/passwd or no users were returned."

        login_users = []

        for line in output.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue

            parts = line.split(":")
            if len(parts) < 7:
                continue

            username = parts[0].strip()
            shell = parts[6].strip()

            if not username:
                continue

            if shell in self.NON_LOGIN_SHELLS:
                continue

            login_users.append(username)

        unique_users = sorted(set(login_users))

        if not unique_users:
            return "No users with interactive login shells were detected."

        return (
            f"Users that can log in to this Linux machine: {', '.join(unique_users)}."
        ) 