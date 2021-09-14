from typing import NoReturn


def assert_never(x: NoReturn) -> NoReturn:
    """
    A hint to the typechecker that a branch can never occur.
    """
    assert False, f"unhandled type: {type(x).__name__}"  # pragma: no cover
