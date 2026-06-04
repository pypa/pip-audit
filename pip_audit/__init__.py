"""
The `pip_audit` APIs.
"""

import truststore

__version__ = "2.10.0"

# Injecting all certificate authorities installed on the system into SSL
# context for all HTTP calls.
truststore.inject_into_ssl()
