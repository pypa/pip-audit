"""
Interfaces for for propagating feedback from the API to provide responsive progress indicators as
well as a progress spinner implementation for use with CLI applications.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

from progress.spinner import Spinner as BaseSpinner  # type: ignore


class AuditState(ABC):
    """
    A state-bearing object that gets passed throughout the `pip_audit` dependency
    collection and auditing APIs.

    Non-UI consumers of `pip_audit` should have no need for subclasses of `AuditState`:
    its primary use is in giving the UI enough state to provide responsive
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
        """
        Create an instance of the `pip-audit` state for usage within a `with` statement.
        """
        return self

    def __exit__(self, _exc_type, _exc_value, _exc_traceback):  # pragma: no cover
        """
        Helper to ensure `finalize` gets called when the `pip-audit` state falls out of scope of a
        `with` statement.
        """
        self.finalize()


class AuditSpinner(AuditState, BaseSpinner):  # pragma: no cover
    """
    A progress spinner for the `pip-audit` CLI.

    The `pip-audit` API takes objects of type `AuditState` in various places. Users can supply an
    instance of `AuditSpinner` to get basic feedback via a progress spinner.
    """

    def __init__(self, message: str = "", **kwargs: Dict[str, Any]):
        """
        Create a new `AuditSpinner`.

        `message` is the initial text that the progress spinner should display.

        Any remaining keyword arguments are forwarded onto the constructor of the underlying
        `BaseSpinner` implementation.
        """

        super().__init__(message=message, **kwargs)

    def update(self) -> None:
        """
        Update the progress spinner.

        This method is overriden from `BaseSpinner` to customize the appearance of the spinner and
        should not be called directly.
        """
        i = self.index % len(self.phases)
        line = f"{self.phases[i]} {self.message}"
        self.writeln(line)

    def update_state(self, message: str) -> None:
        """
        Update the state message for the progress spinner.

        This method is overriden from `AuditState` to update the spinner with feedback from the API
        and should not be called directly.
        """
        self.message = message
        self.next()

    def finalize(self) -> None:
        """
        Cleanup the spinner output so it doesn't get combined with subsequent `stderr` output.
        """
        self.finish()
