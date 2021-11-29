"""
Interfaces for for propagating feedback from the API to provide responsive progress indicators as
well as a progress spinner implementation for use with CLI applications.
"""

import logging
import os
from abc import ABC, abstractmethod
from logging.handlers import MemoryHandler
from typing import Any, Dict, List

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
    def initialize(self) -> None:
        """
        Called when `pip-audit`'s state is initializing. Implementors should override this to do
        nothing if their state management requires no initialization step outside of the
        constructor.
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

        self.initialize()
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

        # Keep the target set to `None` to ensure that the logs don't get written until the spinner
        # has finished writing output, regardless of the capacity argument
        self.log_handler = MemoryHandler(
            0, flushLevel=logging.ERROR, target=None, flushOnClose=False
        )
        self.prev_handlers: List[logging.Handler] = []

    def _writeln_truncated(self, line: str):
        """
        Wraps `BaseSpinner.writeln`, providing reasonable truncation behavior
        when a line would otherwise overflow its terminal row and cause the progress
        bar to break.
        """
        if not (self.file and self.is_tty()):
            return

        columns, _ = os.get_terminal_size(self.file.fileno())
        if columns > 4 and len(line) >= columns:
            line = f"{line[0:columns - 4]} ..."
        else:
            line = line[0:columns]

        self.writeln(line)

    def update(self) -> None:
        """
        Update the progress spinner.

        This method is overriden from `BaseSpinner` to customize the appearance of the spinner and
        should not be called directly.
        """
        i = self.index % len(self.phases)
        line = f"{self.phases[i]} {self.message}"
        self._writeln_truncated(line)

    def update_state(self, message: str) -> None:
        """
        Update the state message for the progress spinner.

        This method is overriden from `AuditState` to update the spinner with feedback from the API
        and should not be called directly.
        """
        self.message = message
        self.next()

    def initialize(self) -> None:
        """
        Redirect logging to an in-memory log handler so that it doesn't get mixed in with the
        spinner output.
        """
        # Remove all existing log handlers
        #
        # We're recording them here since we'll want to restore them once the spinner falls out of
        # scope
        root_logger = logging.root
        for handler in root_logger.handlers:
            self.prev_handlers.append(handler)
        for handler in self.prev_handlers:
            root_logger.removeHandler(handler)

        # Redirect logging to our in-memory handler that will buffer the log lines
        root_logger.addHandler(self.log_handler)

    def finalize(self) -> None:
        """
        Cleanup the spinner output so it doesn't get combined with subsequent `stderr` output and
        flush any logs that were recorded while the spinner was active.
        """
        self.finish()

        # Now that the spinner is complete, flush the logs
        root_logger = logging.root
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        self.log_handler.setTarget(stream_handler)
        self.log_handler.flush()

        # Restore the original log handlers
        root_logger.removeHandler(self.log_handler)
        for handler in self.prev_handlers:
            root_logger.addHandler(handler)
