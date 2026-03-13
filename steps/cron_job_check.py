from steps.base import ReportStep


class CronJobsCheckStep(ReportStep):
    name = "Cron jobs check"

    # Extend this list in the future if more default jobs should be ignored
    DEFAULT_JOB_NAMES = {
        "0hourly",
        "logrotate",
        "man-db",
        "mlocate",
        "tmpwatch",
        "updatedb",
    }

    def command(self) -> str:
        return r"""
sh -c '
echo "SERVICE:";
(systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null || echo inactive)

echo "CRONTAB:";
cat /etc/crontab 2>/dev/null

echo "CROND_DIR:";
ls /etc/cron.d 2>/dev/null

echo "HOURLY:";
ls /etc/cron.hourly 2>/dev/null

echo "DAILY:";
ls /etc/cron.daily 2>/dev/null

echo "WEEKLY:";
ls /etc/cron.weekly 2>/dev/null

echo "MONTHLY:";
ls /etc/cron.monthly 2>/dev/null
'
"""

    def analyze(self, output: str) -> str:
        lines = [line.strip() for line in output.splitlines()]

        service_running = False
        current_section = None
        non_default_jobs = []

        for line in lines:
            if not line:
                continue

            if line.endswith(":"):
                current_section = line[:-1]
                continue

            if current_section == "SERVICE":
                if line == "active":
                    service_running = True

            if current_section in {"CROND_DIR", "HOURLY", "DAILY", "WEEKLY", "MONTHLY"}:
                job_name = line.strip()
                if job_name and job_name not in self.DEFAULT_JOB_NAMES:
                    non_default_jobs.append(job_name)

            if current_section == "CRONTAB":
                if line.startswith("#"):
                    continue
                if line.strip():
                    non_default_jobs.append(f"/etc/crontab entry: {line}")

        cron_status = "running" if service_running else "not running"

        if not non_default_jobs:
            return f"Cron service is {cron_status}. No non-default cron tasks detected."

        jobs_text = "; ".join(sorted(set(non_default_jobs)))

        return (
            f"Cron service is {cron_status}. "
            f"Non-default cron tasks detected: {jobs_text}."
        ) 