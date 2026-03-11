from steps.base import ReportStep


class UsersLoggedInStep(ReportStep):
    name = "Users logged in"

    def command(self) -> str:
        return "who"

    def analyze(self, output: str) -> str:
        if not output:
            return "No users are currently logged in."

        lines = [line for line in output.splitlines() if line.strip()]
        usernames = [line.split()[0] for line in lines if line.split()]
        unique_users = sorted(set(usernames))

        return (
            f"Currently logged in sessions: {len(lines)}. "
            f"Logged in users: {', '.join(unique_users)}."
        )