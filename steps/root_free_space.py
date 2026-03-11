from steps.base import ReportStep


class RootFreeSpaceStep(ReportStep):
    name = "Free space on root folder"

    def command(self) -> str:
        return "df -h / | tail -1"

    def analyze(self, output: str) -> str:
        parts = output.split()
        if len(parts) < 6:
            return f"Could not parse disk information from output: {output}"

        filesystem, size, used, avail, use_percent, mountpoint = parts[:6]

        return (
            f"Root filesystem '{filesystem}' mounted on '{mountpoint}' has "
            f"{avail} free out of {size} total. Used: {used} ({use_percent})."
        )