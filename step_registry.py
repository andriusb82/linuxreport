from __future__ import annotations

from typing import List, Type

from steps.base import ReportStep
from steps.cpu_memory import CpuMemoryStep
from steps.root_free_space import RootFreeSpaceStep
from steps.users_logged_in import UsersLoggedInStep


class StepRegistry:
    def __init__(self) -> None:
        self._step_classes: List[Type[ReportStep]] = [
            UsersLoggedInStep,
            RootFreeSpaceStep,
            CpuMemoryStep,
        ]

    def build_all_steps(self) -> List[ReportStep]:
        return [step_cls(step_id=index + 1) for index, step_cls in enumerate(self._step_classes)]

    def help_text(self) -> str:
        lines = ["Available steps:"]
        for index, step_cls in enumerate(self._step_classes, start=1):
            lines.append(f"  {index}: {step_cls.name}")
        return "\n".join(lines)