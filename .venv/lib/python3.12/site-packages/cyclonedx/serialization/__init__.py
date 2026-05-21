# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""
Set of helper classes for use with ``serializable`` when conducting (de-)serialization.
"""

import sys
from typing import Any, Optional
from uuid import UUID

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL
from py_serializable.helpers import BaseHelper

if sys.version_info >= (3, 13):
    from warnings import deprecated
else:
    from typing_extensions import deprecated

from ..exception.serialization import CycloneDxDeserializationException, SerializationOfUnexpectedValueException
from ..model.bom_ref import BomRef
from ..model.license import _LicenseRepositorySerializationHelper


@deprecated('Use :class:`BomRef` instead.')
class BomRefHelper(BaseHelper):
    """**DEPRECATED** in favour of :class:`BomRef`.

    .. deprecated:: 8.6
       Use :class:`BomRef` instead.
    """

    # TODO: remove, no longer needed

    @classmethod
    def serialize(cls, o: Any) -> Optional[str]:
        return BomRef.serialize(o)

    @classmethod
    def deserialize(cls, o: Any) -> BomRef:
        return BomRef.deserialize(o)


class PackageUrl(BaseHelper):

    @classmethod
    def serialize(cls, o: Any, ) -> str:
        if isinstance(o, PackageURL):
            return str(o.to_string())
        raise SerializationOfUnexpectedValueException(
            f'Attempt to serialize a non-PackageURL: {o!r}')

    @classmethod
    def deserialize(cls, o: Any) -> PackageURL:
        try:
            return PackageURL.from_string(purl=str(o))
        except ValueError as err:
            raise CycloneDxDeserializationException(
                f'PURL string supplied does not parse: {o!r}'
            ) from err


class UrnUuidHelper(BaseHelper):

    @classmethod
    def serialize(cls, o: Any) -> str:
        if isinstance(o, UUID):
            return o.urn
        raise SerializationOfUnexpectedValueException(
            f'Attempt to serialize a non-UUID: {o!r}')

    @classmethod
    def deserialize(cls, o: Any) -> UUID:
        try:
            return UUID(str(o))
        except ValueError as err:
            raise CycloneDxDeserializationException(
                f'UUID string supplied does not parse: {o!r}'
            ) from err


@deprecated('No public API planned for replacing this,')
class LicenseRepositoryHelper(_LicenseRepositorySerializationHelper):
    """**DEPRECATED**

    .. deprecated:: 8.6
       No public API planned for replacing this,
    """

    # TODO: remove, no longer needed

    pass
