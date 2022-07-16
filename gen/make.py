# -*- coding: utf-8 -*-

import collections
import keyword
import os
import re
import shutil
import subprocess  # nosec: B404
import sys
import textwrap

import bs4
import html2text

ROOT = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.abspath(os.path.join(ROOT, '..', 'zlogging', 'enum'))
os.makedirs(PATH, exist_ok=True)
shutil.rmtree(PATH)
os.makedirs(PATH, exist_ok=True)

# regular expression
REGEX_ENUM = re.compile(r'((?P<namespace>[_a-z]+[_a-z0-9]*)::)?(?P<enum>[_a-z]+[_a-z0-9]*)', re.IGNORECASE)
REGEX_LINK = re.compile(r'\[(?P<name>.*?)\]\(.*?\)', re.IGNORECASE)

# file template
TEMPLATE_ENUM = '''\
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Namespace: ``{namespace}``."""

from zlogging._compat import enum
'''

TEMPLATE_INIT = '''\
# -*- coding: utf-8 -*-
# pylint: disable=ungrouped-imports,duplicate-key
"""Bro/Zeek enum namespace."""

import builtins
import warnings
from typing import TYPE_CHECKING

from zlogging._exc import BroDeprecationWarning
'''

TEMPLATE_FUNC = '''\
def globals(*namespaces: 'str', bare: 'bool' = False) -> 'dict[str, Enum]':  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: Namespaces to be loaded.
        bare: If ``True``, do not load ``zeek`` namespace by default.

    Returns:
        Global enum namespace.

    Warns:
        BroDeprecationWarning: If ``bro`` namespace used.

    Raises:
        :exc:`ValueError`: If ``namespace`` is not defined.

    Note:
        For back-port compatibility, the ``bro`` namespace is an alias of the
        ``zeek`` namespace.

    """
    if bare:
        enum_data = {}  # type: dict[str, Enum]
    else:
        enum_data = _enum_zeek.copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = builtins.globals().get('_enum_%s' % namespace)  # pylint: disable=consider-using-f-string
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)  # pylint: disable=consider-using-f-string
        enum_data.update(enum_dict)
    return enum_data
'''


file_list = []  # type: list[str]
for dirpath, _, filenames in os.walk(os.path.join(ROOT, 'sources')):
    file_list.extend(map(
        lambda name: os.path.join(ROOT, 'sources', dirpath, name),  # pylint: disable=cell-var-from-loop
        filter(lambda name: os.path.splitext(name)[1] == '.html', filenames)
    ))

# namespace, enum, name
enum_records = []  # type: list[tuple[str, str, str, str]]

# postpone checks
dest_list = []
for html_file in sorted(file_list):
    print(f'+ {html_file}')
    with open(html_file, encoding='utf-8') as file:
        html = file.read()

    soup = bs4.BeautifulSoup(html, 'html5lib')
    for tag in soup.select('dl.type'):
        descname = tag.select('dt code.descname')
        if not descname:
            continue
        name = descname[0].text.strip()
        print(f'++ {name}')

        selected = tag.select('dd td p.first span.pre')
        if not selected:
            continue
        type = selected[0].text.strip()  # pylint: disable=redefined-builtin
        if type != 'enum':
            continue

        enum_list = []
        for dl in tag.select('dd td dl.enum'):
            enum_name = dl.select('dt code.descname')[0].text.strip()
            enum_docs = dl.select('dd')[0].text.strip()
            enum_list.append((enum_name, enum_docs))

        docs_list = []
        for p in tag.select('dd')[0].children:
            if p.name != 'p':
                continue
            docs = '\n    '.join(
                textwrap.wrap(
                    REGEX_LINK.sub(
                        r'\g<name>',
                        html2text.html2text(
                            str(p).replace('\n', ' ')
                        ).replace('\n', ' ')
                    ).replace('`', '``').strip(),
                    100, break_on_hyphens=False,
                )
            )
            if not docs.endswith('.'):
                docs += '.'
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
            with open(dest, 'w', encoding='utf-8') as file:
                file.write(TEMPLATE_ENUM.format(namespace=namespace))
        docs_list.insert(0, f'Enum: ``{name}``.')

        html_path = os.path.splitext(os.path.relpath(html_file, os.path.join(ROOT, 'sources')))[0]
        docs_list.append(f'See Also:\n        `{html_path} <https://docs.zeek.org/en/stable/scripts/{html_path}.html#type-{name}>`__\n\n    ')  # pylint: disable=line-too-long

        enum_docs = '\n\n    '.join(docs_list)
        with open(dest, 'a', encoding='utf-8') as file:
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
                    safe_enum = safe_enum.replace('::', '_')
                if safe_docs:
                    print(f'    #: {safe_docs}', file=file)
                if keyword.iskeyword(safe_enum):
                    print(f'    {enum_name}[{safe_enum!r}] = enum.auto()', file=file)
                else:
                    print(f'    {safe_enum} = enum.auto()', file=file)
                if index != length:
                    print('', file=file)
                enum_records.append((namespace, enum_name, enum, safe_enum))

        dest_list.append(dest)

imported = []
enum_line = collections.defaultdict(list)
with open(os.path.join(PATH, '__init__.py'), 'w', encoding='utf-8') as file:
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
        if keyword.iskeyword(enum_name):
            enum_line[safe_namespace].append(f'    {safe_name!r}: {namespace}_{enum}[{enum_name!r}],  # type: ignore[misc]')  # pylint: disable=line-too-long
        else:
            enum_line[safe_namespace].append(f'    {enum_name!r}: {namespace}_{enum}.{enum_name},')
    print('', file=file)
    print("__all__ = ['globals']", file=file)
    print('', file=file)
    print('if TYPE_CHECKING:', file=file)
    print('    from enum import Enum', file=file)
    print('', file=file)

    for namespace in sorted(enum_line):
        print(f'_enum_{namespace} = {{', file=file)
        for line in sorted(enum_line[namespace]):
            print(line, file=file)
        print('}', file=file)
        print('', file=file)
    print('', file=file)
    file.write(TEMPLATE_FUNC)

subprocess.check_call([sys.executable, os.path.join(PATH, '__init__.py')])  # nosec: B603
for dest in dest_list:
    subprocess.check_call([sys.executable, dest])  # nosec: B603
