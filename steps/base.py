from __future__ import annotations

from abc import ABC, abstractmethod

from connection import SSHConnectionManager
from models import StepResult


class ReportStep(ABC):
    name: str = "Unnamed step"

    def __init__(self, step_id: int) -> None:
        self.step_id = step_id

    @abstractmethod
    def command(self) -> str:
        pass

    @abstractmethod
    def analyze(self, output: str) -> str:
        pass

    def run(self, connection: SSHConnectionManager) -> StepResult:
        output, error, exit_code = connection.execute(self.command())

        if exit_code != 0:
            conclusion = f"Command failed with exit code {exit_code}. Error: {error or 'unknown error'}"
        else:
            conclusion = self.analyze(output)

        return StepResult(
            step_id=self.step_id,
            step_name=self.name,
            conclusion=conclusion,
        )