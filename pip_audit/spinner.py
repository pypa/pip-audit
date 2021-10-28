from typing import Any, Dict

from progress.spinner import Spinner as BaseSpinner  # type: ignore


class AuditSpinner(BaseSpinner):  # pragma: no cover
    def __init__(self, message: str = "", **kwargs: Dict[str, Any]):
        super().__init__(message=message, **kwargs)
        self._base_message = self.message

    def update(self) -> None:
        i = self.index % len(self.phases)
        line = f"{self.phases[i]} {self.message}"
        self.writeln(line)

    def update_message(self, message: str) -> None:
        self.message = message
        self.next()
