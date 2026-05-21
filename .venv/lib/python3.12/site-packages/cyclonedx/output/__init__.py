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
Set of classes and methods for outputting our libraries internal Bom model to CycloneDX documents in varying formats
and according to different versions of the CycloneDX schema standard.
"""

import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from itertools import chain
from random import random
from typing import TYPE_CHECKING, Any, Literal, Optional, Union, overload

from ..schema import OutputFormat, SchemaVersion

if TYPE_CHECKING:  # pragma: no cover
    from ..model.bom import Bom
    from ..model.bom_ref import BomRef
    from .json import Json as JsonOutputter
    from .xml import Xml as XmlOutputter


class BaseOutput(ABC):

    def __init__(self, bom: 'Bom', **kwargs: int) -> None:
        super().__init__(**kwargs)
        self._bom = bom
        self._generated: bool = False

    @property
    @abstractmethod
    def schema_version(self) -> SchemaVersion:
        ...  # pragma: no cover

    @property
    @abstractmethod
    def output_format(self) -> OutputFormat:
        ...  # pragma: no cover

    @property
    def generated(self) -> bool:
        return self._generated

    @generated.setter
    def generated(self, generated: bool) -> None:
        self._generated = generated

    def get_bom(self) -> 'Bom':
        return self._bom

    def set_bom(self, bom: 'Bom') -> None:
        self._bom = bom

    @abstractmethod
    def generate(self, force_regeneration: bool = False) -> None:
        ...  # pragma: no cover

    @abstractmethod
    def output_as_string(self, *,
                         indent: Optional[Union[int, str]] = None,
                         **kwargs: Any) -> str:
        ...  # pragma: no cover

    def output_to_file(self, filename: str, allow_overwrite: bool = False, *,
                       indent: Optional[Union[int, str]] = None,
                       **kwargs: Any) -> None:
        # Check directory writable
        output_filename = os.path.realpath(filename)
        output_directory = os.path.dirname(output_filename)
        if not os.access(output_directory, os.W_OK):
            raise PermissionError(output_directory)
        if os.path.exists(output_filename) and not allow_overwrite:
            raise FileExistsError(output_filename)
        with open(output_filename, mode='wb') as f_out:
            f_out.write(self.output_as_string(indent=indent).encode('utf-8'))


@overload
def make_outputter(bom: 'Bom', output_format: Literal[OutputFormat.JSON],
                   schema_version: SchemaVersion) -> 'JsonOutputter':
    ...  # pragma: no cover


@overload
def make_outputter(bom: 'Bom', output_format: Literal[OutputFormat.XML],
                   schema_version: SchemaVersion) -> 'XmlOutputter':
    ...  # pragma: no cover


@overload
def make_outputter(bom: 'Bom', output_format: OutputFormat,
                   schema_version: SchemaVersion) -> Union['XmlOutputter', 'JsonOutputter']:
    ...  # pragma: no cover


def make_outputter(bom: 'Bom', output_format: OutputFormat, schema_version: SchemaVersion) -> BaseOutput:
    """
    Helper method to quickly get the correct output class/formatter.

    Pass in your BOM and optionally an output format and schema version (defaults to XML and latest schema version).


    Raises error when no instance could be made.

    :param bom: Bom
    :param output_format: OutputFormat
    :param schema_version: SchemaVersion
    :return: BaseOutput
    """
    if TYPE_CHECKING:  # pragma: no cover
        BY_SCHEMA_VERSION: Mapping[SchemaVersion, type[BaseOutput]]  # noqa:N806
    if OutputFormat.JSON is output_format:
        from .json import BY_SCHEMA_VERSION
    elif OutputFormat.XML is output_format:
        from .xml import BY_SCHEMA_VERSION
    else:
        raise ValueError(f'Unexpected output_format: {output_format!r}')

    klass = BY_SCHEMA_VERSION.get(schema_version, None)
    if klass is None:
        raise ValueError(f'Unknown {output_format.name}/schema_version: {schema_version!r}')
    return klass(bom)


class BomRefDiscriminator:

    def __init__(self, bomrefs: Iterable['BomRef'], prefix: str = 'BomRef') -> None:
        # do not use dict/set here, different BomRefs with same value have same hash and would shadow each other
        self._bomrefs = tuple((bomref, bomref.value) for bomref in bomrefs)
        self._prefix = prefix

    def __enter__(self) -> None:
        self.discriminate()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def discriminate(self) -> None:
        known_values = []
        for bomref, _ in self._bomrefs:
            value = bomref.value
            if value is None or value in known_values:
                value = self._make_unique()
                bomref.value = value
            known_values.append(value)

    def reset(self) -> None:
        for bomref, original_value in self._bomrefs:
            bomref.value = original_value

    def _make_unique(self) -> str:
        return f'{self._prefix}{str(random())[1:]}{str(random())[1:]}'  # nosec B311

    @classmethod
    def from_bom(cls, bom: 'Bom', prefix: str = 'BomRef') -> 'BomRefDiscriminator':
        return cls(chain(
            map(lambda c: c.bom_ref, bom._get_all_components()),
            map(lambda s: s.bom_ref, bom.services),
            map(lambda v: v.bom_ref, bom.vulnerabilities)
        ), prefix)
