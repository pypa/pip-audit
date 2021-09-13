from abc import ABC
from typing import Dict, List

import pip_audit.service as service


class VulnerabilityFormat(ABC):
    def format(
        self, result: Dict[service.Dependency, List[service.VulnerabilityResult]]
    ) -> str:  # pragma: no cover
        raise NotImplementedError
