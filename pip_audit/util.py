from typing import NoReturn  # pragma: no cover


def assert_never(x: NoReturn) -> NoReturn:  # pragma: no cover
    """
    A hint to the typechecker that a branch can never occur.
    """
    assert False, f"unhandled type: {type(x).__name__}"
