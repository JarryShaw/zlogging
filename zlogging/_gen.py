# -*- coding: utf-8 -*-
"""Bro/Zeek enumeration namespace generator."""

import argparse
import collections
import importlib
import keyword
import os
import pathlib
import re
import shutil
import subprocess  # nosec: B404
import sys
import textwrap
import urllib.parse as urllib_parse

###############################################################################
# ``typing`` module support
_local = sys.path.pop(0)
###############################################################################

import bs4
import html2text
import requests

###############################################################################
# ``typing`` module support
sys.path.insert(0, _local)
###############################################################################

ROOT = os.path.dirname(os.path.realpath(__file__))
PATH = os.path.abspath(os.path.join(ROOT, 'enum'))

# regular expression
REGEX_ENUM = re.compile(r'((?P<namespace>([_a-z]+[_a-z0-9]*)(::[_a-z]+[_a-z0-9]*)*)::)?(?P<enum>[_a-z]+[_a-z0-9]*)', re.IGNORECASE)
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
        enum_data = builtins.globals()['ZLogging::zeek'].copy()
    for namespace in namespaces:
        if namespace == 'bro':
            warnings.warn("Use of 'bro' is deprecated. "
                          "Please use 'zeek' instead.", BroDeprecationWarning)
            namespace = 'zeek'

        enum_dict = builtins.globals().get('ZLogging::%s' % namespace)  # pylint: disable=consider-using-f-string
        if enum_dict is None:
            raise ValueError('undefined namespace: %s' % namespace)  # pylint: disable=consider-using-f-string
        enum_data.update(enum_dict)
    return enum_data
'''


def fetch() -> 'None':
    """Fetch Bro/Zeek documentation.

    Args:
        caching: Enable caching files.

    """
    link = 'https://docs.zeek.org/en/stable/script-reference/scripts.html'
    resp = requests.get(link)  # nosec B113
    if not resp.ok:
        raise RuntimeError(resp)

    page = resp.text
    soup = bs4.BeautifulSoup(page, 'html5lib')
    for tag in soup.select('.toctree-wrapper li > a'):
        print(f'+ {tag.text}')

        href = tag.get('href')
        if href is None:
            raise RuntimeError(tag)
        name = pathlib.PurePosixPath(tag.text)
        path = pathlib.Path(os.path.join(ROOT, '_cache', *name.parts))
        if os.path.isfile(f'{path}.html'):
            continue

        dest = urllib_parse.urljoin(link, href)
        docs = requests.get(dest)  # nosec B113
        if not docs.ok:
            raise RuntimeError(docs)

        os.makedirs(path.parent, exist_ok=True)
        with open(f'{path}.html', 'wb') as file:
            file.write(docs.content)


def make() -> 'None':
    """Make Bro/Zeek enumeration namespace."""
    if os.path.exists(PATH):
        shutil.rmtree(PATH)
    os.makedirs(PATH, exist_ok=True)

    file_list = []  # type: list[str]
    for dirpath, _, filenames in os.walk(os.path.join(ROOT, '_cache')):
        file_list.extend(map(
            lambda name: os.path.join(ROOT, '_cache', dirpath, name),  # pylint: disable=cell-var-from-loop
            filter(lambda name: os.path.splitext(name)[1] == '.html', filenames)
        ))

    # namespace, module_name, enum, name, enum_name
    enum_records = []  # type: list[tuple[str, str, str, str, str]]

    # postpone checks
    dest_list = []
    for html_file in sorted(file_list):
        print(f'+ {html_file}')
        with open(html_file, encoding='utf-8') as file:
            html = file.read()

        soup = bs4.BeautifulSoup(html, 'html5lib')
        for tag in soup.select('dl.type'):
            descname = tag.select('dt.sig span.pre')
            if not descname:
                continue
            name = descname[0].text.strip()

            selected = tag.select('dd dl p')
            if not selected:
                print(f'++ {name} (no type)')
                continue

            type = selected[0].text.strip()  # pylint: disable=redefined-builtin
            print(f'++ {name} ({type})')
            if type != 'enum':
                continue

            enum_list = []
            for dl in tag.select('dd dl dl.enum'):
                enum_name = dl.select('dt.sig span.pre')[0].text.strip()
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
            print(f'+++ {namespace}::{enum_name}')

            ns_parts = namespace.replace('::', '_').split('_')
            for index, part in enumerate(ns_parts):
                if part.isupper():
                    ns_parts[index] = part.lower()
                else:
                    ns_parts[index] = re.sub(r'([A-Z])', r'_\1', part).lower().lstrip('_')
            module_name = '_'.join(ns_parts)

            dest = os.path.join(PATH, f'{module_name}.py')
            if not os.path.isfile(dest):
                with open(dest, 'w', encoding='utf-8') as file:
                    file.write(TEMPLATE_ENUM.format(namespace=namespace))
            docs_list.insert(0, f'Enum: ``{name}``.')

            html_path = os.path.splitext(os.path.relpath(html_file, os.path.join(ROOT, '_cache')))[0]
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
                    enum_records.append((namespace, module_name, enum_name, enum, safe_enum))

            dest_list.append(dest)

    imported = []
    enum_line = collections.defaultdict(list)
    with open(os.path.join(PATH, '__init__.py'), 'w', encoding='utf-8') as file:
        file.write(TEMPLATE_INIT)
        for namespace, module_name, enum, name, enum_name in sorted(enum_records):
            safe_namespace = namespace.replace('::', '_')
            if (namespace, enum) not in imported:
                print(f'from zlogging.enum.{module_name} import {enum} as {safe_namespace}_{enum}', file=file)
                imported.append((namespace, enum))

                enum_line[namespace].append(f'    {enum!r}: {safe_namespace}_{enum},')

            match = REGEX_ENUM.fullmatch(name)
            if match is None:
                raise ValueError(name)
            match_namespace = match.group('namespace')
            if match_namespace is None:
                match_namespace = namespace
            safe_name = match.group('enum')
            if keyword.iskeyword(enum_name):
                enum_line[match_namespace].append(f'    {safe_name!r}: {safe_namespace}_{enum}[{enum_name!r}],  # type: ignore[misc]')  # pylint: disable=line-too-long
            else:
                enum_line[match_namespace].append(f'    {enum_name!r}: {safe_namespace}_{enum}.{enum_name},')
        print('', file=file)
        print("__all__ = ['globals']", file=file)
        print('', file=file)
        print('if TYPE_CHECKING:', file=file)
        print('    from enum import Enum', file=file)
        print('', file=file)

        for namespace in sorted(enum_line):
            print(f"builtins.globals()['ZLogging::{namespace}'] = {{", file=file)
            for line in sorted(enum_line[namespace]):
                print(line, file=file)
            print('}', file=file)
            print('', file=file)
        print('', file=file)
        file.write(TEMPLATE_FUNC)


def test() -> 'None':
    """Test the generated code."""
    module = importlib.import_module('zlogging.enum')
    assert 'tcp' in module.globals()  # nosec B101

    for dest in filter(lambda x: x.endswith('.py'), os.listdir(PATH)):
        if dest == '__init__.py':
            continue

        module_name = os.path.splitext(dest)[0]
        importlib.import_module(f'zlogging.enum.{module_name}')


def main() -> 'int':
    """Entrypoint."""
    parser = argparse.ArgumentParser(prog='zlogging-vendor',
                                     description='update Bro/Zeek enumeration namespace')
    parser.add_argument('-c', '--caching', action='store_true',
                        help='use cached downloaded files')

    args = parser.parse_args()
    if not args.caching and os.path.exists(os.path.join(ROOT, '_cache')):
        shutil.rmtree(os.path.join(ROOT, '_cache'))

    fetch()
    make()
    test()

    return 0


if __name__ == '__main__':
    sys.exit(main())
