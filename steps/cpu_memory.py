from steps.base import ReportStep


class CpuMemoryStep(ReportStep):
    name = "Current CPU load and free memory"

    def command(self) -> str:
        return r"""sh -c 'echo "LOAD:"; uptime; echo "MEM:"; free -m'"""

    def analyze(self, output: str) -> str:
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        uptime_line = ""
        mem_line = ""

        in_mem_section = False
        for line in lines:
            if line.startswith("LOAD:"):
                continue
            if line.startswith("MEM:"):
                in_mem_section = True
                continue

            if not in_mem_section and not uptime_line:
                uptime_line = line

            if in_mem_section and line.lower().startswith("mem:"):
                mem_line = line

        load_text = "CPU load information unavailable"
        memory_text = "Memory information unavailable"

        if uptime_line and "load average" in uptime_line:
            load_text = uptime_line.split("load average:")[-1].strip()

        if mem_line:
            parts = mem_line.split()
            if len(parts) >= 7:
                total_mb = parts[1]
                used_mb = parts[2]
                free_mb = parts[3]
                available_mb = parts[6]
                memory_text = (
                    f"Memory total: {total_mb} MB, used: {used_mb} MB, "
                    f"free: {free_mb} MB, available: {available_mb} MB"
                )

        return f"CPU load averages: {load_text}. {memory_text}."