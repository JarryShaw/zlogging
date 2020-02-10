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
"""Namespace: {namespace}."""

import enum
'''
TEMPLATE_INIT = '''\
# -*- coding: utf-8 -*-
"""Bro/Zeek enum namespace."""

import warnings

import zlogging._typing as typing
from zlogging._exc import BroDeprecationWarning
'''
TEMPLATE_FUNC = '''\
def globals(*namespaces: typing.Args, bare: bool = False) -> typing.Dict[str, typing.Enum]:  # pylint: disable=redefined-builtin
    """Generate Bro/Zeek ``enum`` namespace.

    Args:
        *namespaces: namespaces to be loaded
        bare: if ``True``, do not load ``zeek` namespace by default

    Returns:
        :obj:`Dict[str, Enum]`: global enum namespace

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
            docs = p.text.replace('\n', '\n    ')
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
        docs_list.append(f'\n    c.f. `{html_path} <https://docs.zeek.org/en/stable/scripts/{html_path}.html>`__\n    ')
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
                safe_docs = docs.replace('\n', '\n    # ')
                safe_enum = re.sub(f'{namespace}::', '', enum)
                if safe_docs:
                    print(f'    # {safe_docs}', file=file)
                print(f'    {enum_name}[{safe_enum!r}] = enum.auto()', file=file)
                if index != length:
                    print('', file=file)
                enum_records.append((namespace, enum_name, safe_enum))

        subprocess.check_call([sys.executable, dest])

imported = list()
enum_line = collections.defaultdict(list)
with open(os.path.join(PATH, '__init__.py'), 'w') as file:
    file.write(TEMPLATE_INIT)
    for namespace, enum, name in sorted(enum_records):
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
        enum_line[safe_namespace].append(f'    {safe_name!r}: {namespace}_{enum}[{name!r}],')
    print('', file=file)
    print("__all__ = ['globals']", file=file)
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
