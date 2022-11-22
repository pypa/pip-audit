"""
Interfaces for for propagating feedback from the API to provide responsive progress indicators as
well as a progress spinner implementation for use with CLI applications.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from logging.handlers import MemoryHandler
from typing import Any, Sequence

from rich.console import Console


class AuditState:
    """
    An object that handles abstract "updates" to `pip-audit`'s state.

    Non-UI consumers of `pip-audit` (via `pip_audit`) should have no need for
    this class, and can leave it as a default construction in whatever signatures
    it appears in. Its primary use is internal and UI-specific: it exists solely
    to give the CLI enough state for a responsive progress indicator during
    user requests.
    """

    def __init__(self, *, members: Sequence["_StateActor"] = []):
        """
        Create a new `AuditState` with the given member list.
        """

        self._members = members

    def update_state(self, message: str) -> None:
        """
        Called whenever `pip_audit`'s internal state changes in a way that's meaningful to
        expose to a user.

        `message` is the message to present to the user.
        """

        for member in self._members:
            member.update_state(message)

    def initialize(self) -> None:
        """
        Called when `pip-audit`'s state is initializing.
        """

        for member in self._members:
            member.initialize()

    def finalize(self) -> None:
        """
        Called when `pip_audit`'s state is "done" changing.
        """
        for member in self._members:
            member.finalize()

    def __enter__(self) -> "AuditState":  # pragma: no cover
        """
        Create an instance of the `pip-audit` state for usage within a `with` statement.
        """

        self.initialize()
        return self

    def __exit__(
        self, _exc_type: Any, _exc_value: Any, _exc_traceback: Any
    ) -> None:  # pragma: no cover
        """
        Helper to ensure `finalize` gets called when the `pip-audit` state falls out of scope of a
        `with` statement.
        """
        self.finalize()


class _StateActor(ABC):
    @abstractmethod
    def update_state(self, message: str) -> None:
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def initialize(self) -> None:
        """
        Called when `pip-audit`'s state is initializing. Implementors should
        override this to do nothing if their state management requires no
        initialization step.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def finalize(self) -> None:
        """
        Called when the overlaying `AuditState` is "done," i.e. `pip-audit`'s
        state is done changing. Implementors should override this to do nothing
        if their state management requires no finalization step.
        """
        raise NotImplementedError  # pragma: no cover


class AuditSpinner(_StateActor):  # pragma: no cover
    """
    A progress spinner for `pip-audit`, using `rich.status`'s spinner support
    under the hood.
    """

    def __init__(self, message: str = "") -> None:
        """
        Initialize the `AuditSpinner`.
        """

        self._console = Console()
        # NOTE: audits can be quite fast, so we need a pretty high refresh rate here.
        self._spinner = self._console.status(message, spinner="line", refresh_per_second=30)

        # Keep the target set to `None` to ensure that the logs don't get written until the spinner
        # has finished writing output, regardless of the capacity argument
        self.log_handler = MemoryHandler(
            0, flushLevel=logging.ERROR, target=None, flushOnClose=False
        )
        self.prev_handlers: list[logging.Handler] = []

    def update_state(self, message: str) -> None:
        """
        Update the spinner's state.
        """

        self._spinner.update(message)

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

        self._spinner.start()

    def finalize(self) -> None:
        """
        Cleanup the spinner output so it doesn't get combined with subsequent `stderr` output and
        flush any logs that were recorded while the spinner was active.
        """

        self._spinner.stop()

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
