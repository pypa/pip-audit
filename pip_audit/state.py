from abc import ABC, abstractmethod
from typing import Any, Dict

from progress.spinner import Spinner as BaseSpinner  # type: ignore


class AuditState(ABC):
    """
    A state-bearing object that gets passed throughout the `pip_audit` dependency
    collection and auditing APIs.

    Non-CLI consumers of `pip_audit` should have no need for subclasses of `AuditState`:
    its primary use is in giving the CLI enough state to provide responsive
    progress indicators during user requests.
    """

    @abstractmethod
    def update_state(self, message: str) -> None:
        """
        Called whenever `pip_audit`'s internal state changes in a way that's meaningful to
        expose to a user.

        `message` is the message to present to the user.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def finalize(self) -> None:
        """
        Called when `pip_audit`'s state is "done" changing. Implementors should
        override this to do nothing if their state management requires no
        cleanup or finalization step.
        """
        raise NotImplementedError  # pragma: no cover

    def __enter__(self) -> "AuditState":  # pragma: no cover
        return self

    def __exit__(self, _exc_type, _exc_value, _exc_traceback):  # pragma: no cover
        self.finalize()


class AuditSpinner(AuditState, BaseSpinner):  # pragma: no cover
    def __init__(self, message: str = "", **kwargs: Dict[str, Any]):
        super().__init__(message=message, **kwargs)
        self._base_message = self.message

    def update(self) -> None:
        i = self.index % len(self.phases)
        line = f"{self.phases[i]} {self.message}"
        self.writeln(line)

    def update_state(self, message: str) -> None:
        self.message = message
        self.next()

    def finalize(self) -> None:
        self.finish()
