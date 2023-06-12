# -*- coding: utf-8 -*-

import importlib
import os
import re
import shutil
from typing import cast

import zlogging._gen as zlogging_gen

DOCS = os.path.join(os.path.dirname(__file__), '..', 'docs', 'source', 'enum')
if os.path.exists(DOCS):
    shutil.rmtree(DOCS)
os.makedirs(DOCS, exist_ok=True)

file_list = []  # type: list[str]
for dest in filter(lambda x: x.endswith('.py'), os.listdir(zlogging_gen.PATH)):
    if dest == '__init__.py':
        continue

    module_name = os.path.splitext(dest)[0]
    module = importlib.import_module(f'zlogging.enum.{module_name}')

    ns_match = re.match(r'^Namespace: ``(?P<name>.+)``\.$', cast('str', module.__doc__))
    if ns_match is None:
        raise ValueError(f'namespace unknown: {module_name}')
    ns_name = ns_match.group('name')

    with open(os.path.join(DOCS, f'{module_name}.rst'), 'w') as file:
        print(f'''\
``{ns_name}`` Namespace
{'-' * (len(ns_name) + 14)}

.. automodule:: zlogging.enum.{module_name}
   :members:
   :undoc-members:
   :show-inheritance:
   :noindex:
'''.strip(), file=file)

    file_list.append(module_name)

linesep = '\n'
with open(os.path.join(DOCS, 'index.rst'), 'w') as file:
    print(f'''\
Enum Namespace
==============

.. module:: zlogging.enum

.. toctree::
   :maxdepth: 2

{''.join(f'   {module_name}{linesep}' for module_name in sorted(file_list))}
.. autofunction:: zlogging.enum.globals
'''.strip(), file=file)
