from dataclasses import dataclass
from datetime import datetime
from typing import List


@dataclass
class GeneralReportInfo:
    hostname: str
    ip_address: str
    generated_at: datetime


@dataclass
class StepResult:
    step_id: int
    step_name: str
    conclusion: str


@dataclass
class FinalReport:
    general_info: GeneralReportInfo
    step_results: List[StepResult]