"""
The `python -m pip_audit` entrypoint.
"""

if __name__ == "__main__":
    from pip_audit._cli import audit

    audit()
