# -*- coding: utf-8 -*-

import os
import pathlib
import urllib.parse

import bs4
import requests

ROOT = os.path.dirname(os.path.abspath(__file__))
# enable caching files
CACHING = True

link = 'https://docs.zeek.org/en/stable/script-reference/scripts.html'
resp = requests.get(link)
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
    path = pathlib.Path(os.path.join(ROOT, 'sources', *name.parts))
    if CACHING and os.path.isfile(f'{path}.html'):
        continue

    dest = urllib.parse.urljoin(link, href)
    docs = requests.get(dest)
    if not docs.ok:
        raise RuntimeError(docs)

    os.makedirs(path.parent, exist_ok=True)
    with open(f'{path}.html', 'wb') as file:
        file.write(docs.content)
