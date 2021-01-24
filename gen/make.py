# -*- coding: utf-8 -*-

import collections
import os
import re
import shutil
import subprocess
import sys

import bs4

ROOT = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.abspath(os.path.join(ROOT, '..', 'zlogging', 'enum'))
os.makedirs(PATH, exist_ok=True)
shutil.rmtree(PATH)
os.makedirs(PATH, exist_ok=True)

# regular expression
REGEX_ENUM = re.compile(r'((?P<namespace>[_a-z]+[_a-z0-9]*)::)?(?P<enum>[_a-z]+[_a-z0-9]*)', re.IGNORECASE)

# file template
TEMPLATE_ENUM = '''\
# -*- coding: utf-8 -*-
"""Namespace: ``{namespace}``."""

from zlogging._compat import enum
'''
TEMPLATE_INIT = '''\
# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports
"""Bro/Zeek enum namespace."""

import warnings
from typing import TYPE_CHECKING

from zlogging._exc import BroDeprecationWarning
'''
TEMPLATE_FUNC = '''\
def globals(*namespaces, bare: bool = False) -> 'Dict[str, Enum]':  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: Namespaces to be loaded.
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Keyword Args:
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Returns:
        :obj:`dict` mapping of :obj:`str` and :obj:`Enum`: Global enum namespace.

    Warns:
        BroDeprecationWarning: If ``bro`` namespace used.

    Raises:
        :exc:`ValueError`: If ``namespace`` is not defined.

    Note:
        For back-port compatibility, the ``bro`` namespace is an alias of the
        ``zeek`` namespace.

    """
    if bare:
        enum_data = dict()
    else:
        enum_data = _enum_zeek.copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = globals().get('_enum_%s' % namespace)
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)
        enum_data.update(enum_dict)
    return enum_data
'''


file_list = list()
for dirpath, _, filenames in os.walk(os.path.join(ROOT, 'sources')):
    file_list.extend(map(
        lambda name: os.path.join(ROOT, 'sources', dirpath, name),  # pylint: disable=cell-var-from-loop
        filter(lambda name: os.path.splitext(name)[1] == '.html', filenames)  # pylint: disable=filter-builtin-not-iterating
    ))

# namespace, enum, name
enum_records = list()

# postpone checks
dest_list = list()
for html_file in sorted(file_list):
    print(f'+ {html_file}')
    with open(html_file) as file:
        html = file.read()

    soup = bs4.BeautifulSoup(html, 'html5lib')
    for tag in soup.select('dl.type'):
        name = tag.select('dt code.descname')[0].text.strip()
        print(f'++ {name}')

        selected = tag.select('dd td p.first span.pre')
        if not selected:
            continue
        type = selected[0].text.strip()  # pylint: disable=redefined-builtin
        if type != 'enum':
            continue

        enum_list = list()
        for dl in tag.select('dd td dl.enum'):
            enum_name = dl.select('dt code.descname')[0].text.strip()
            enum_docs = dl.select('dd')[0].text.strip()
            enum_list.append((enum_name, enum_docs))

        docs_list = list()
        for p in tag.select('dd')[0].children:
            if p.name != 'p':
                continue
            docs = p.text.strip().replace('\n', '\n    ').replace('_', r'\_')
            docs_list.append(docs)

        match = REGEX_ENUM.fullmatch(name)
        if match is None:
            raise ValueError(name)

        namespace = match.group('namespace')
        if namespace is None:
            namespace = 'zeek'
        enum_name = match.group('enum')

        dest = os.path.join(PATH, f'{namespace}.py')
        if not os.path.isfile(dest):
            with open(dest, 'w') as file:
                file.write(TEMPLATE_ENUM.format(namespace=namespace))

        html_path = os.path.splitext(os.path.relpath(html_file, os.path.join(ROOT, 'sources')))[0]
        if docs_list:
            docs_list.append(f'c.f. `{html_path} <https://docs.zeek.org/en/stable/scripts/{html_path}.html#type-{name}>`__\n\n    ')  # pylint: disable=line-too-long
        else:
            docs_list.append(f'c.f. `{html_path} <https://docs.zeek.org/en/stable/scripts/{html_path}.html#type-{name}>`__')  # pylint: disable=line-too-long
        enum_docs = '\n\n    '.join(docs_list)
        with open(dest, 'a') as file:
            print('', file=file)
            print('', file=file)
            print('@enum.unique', file=file)
            print(f'class {enum_name}(enum.IntFlag):', file=file)
            if enum_docs:
                print(f'    """{enum_docs}"""', file=file)
                print('', file=file)
            print(f"    _ignore_ = '{enum_name} _'", file=file)
            print(f'    {enum_name} = vars()', file=file)
            print('', file=file)

            length = len(enum_list)
            for index, (enum, docs) in enumerate(enum_list, start=1):
                safe_docs = docs.replace('\n', '\n    #: ').replace('_', r'\_')
                safe_enum = re.sub(f'{namespace}::', '', enum)
                if '::' in safe_enum:
                    safe_docs = f'{enum}\n    #: ' + safe_docs
                    safe_enum = safe_enum.replace('::', '__')
                if safe_docs:
                    print(f'    #: {safe_docs}', file=file)
                print(f'    {enum_name}[{safe_enum!r}] = enum.auto()', file=file)
                if index != length:
                    print('', file=file)
                enum_records.append((namespace, enum_name, enum, safe_enum))

        dest_list.append(dest)

imported = list()
enum_line = collections.defaultdict(list)
with open(os.path.join(PATH, '__init__.py'), 'w') as file:
    file.write(TEMPLATE_INIT)
    for namespace, enum, name, enum_name in sorted(enum_records):
        if (namespace, enum) not in imported:
            print(f'from zlogging.enum.{namespace} import {enum} as {namespace}_{enum}', file=file)
            imported.append((namespace, enum))

            enum_line[namespace].append(f'    {enum!r}: {namespace}_{enum},')

        match = REGEX_ENUM.fullmatch(name)
        if match is None:
            raise ValueError(name)
        safe_namespace = match.group('namespace')
        if safe_namespace is None:
            safe_namespace = namespace
        safe_name = match.group('enum')
        enum_line[safe_namespace].append(f'    {safe_name!r}: {namespace}_{enum}[{enum_name!r}],')
    print('', file=file)
    print("__all__ = ['globals']", file=file)
    print('', file=file)
    print('if TYPE_CHECKING:', file=file)
    print('    from enum import Enum', file=file)
    print('    from typing import Dict', file=file)
    print('', file=file)

    for namespace in sorted(enum_line):
        print(f'_enum_{namespace} = {{', file=file)
        for line in sorted(enum_line[namespace]):
            print(line, file=file)
        print('}', file=file)
        print('', file=file)
    print('', file=file)
    file.write(TEMPLATE_FUNC)

subprocess.check_call([sys.executable, os.path.join(PATH, '__init__.py')])
for dest in dest_list:
    subprocess.check_call([sys.executable, dest])
