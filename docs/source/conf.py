# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import datetime
import importlib
import logging
import sys
import typing
from typing import TYPE_CHECKING

import zlogging

if TYPE_CHECKING:
    from typing import Any

    from sphinx.application import Sphinx

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
#logging.basicConfig(level=logging.DEBUG)

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'ZLogging'
copyright = f'2020-{datetime.datetime.today().year}, Jarry Shaw'  # pylint: disable=redefined-builtin
author = 'Jarry Shaw'

# The full version, including alpha/beta/rc tags
release = zlogging.__version__


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.autodoc', 'sphinx.ext.autodoc.typehints',
    'sphinx.ext.napoleon',
    'sphinx_autodoc_typehints',
]

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'broapt': ('https://broapt.jarryshaw.me/en/latest/', None),
    'zeek': ('https://docs.zeek.org/en/stable/', None),
    'bro': ('https://docs.zeek.org/en/stable/', None),
}

autodoc_typehints = 'description'
autodoc_member_order = 'bysource'

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_custom_sections = None

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []  # type: list[str]

#set_type_checking_flag = True

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
html_theme_options = {
    'show_powered_by': False,
    'github_user': 'JarryShaw',
    'github_repo': 'zlogging',
    'github_banner': True,
    'github_type': 'star',
    #'show_related': False,
    #'note_bg': '#FFF59C',
    #'travis_button': True,
    #'codecov_button': True,
}


def reload_module(app: 'Sphinx', what: 'str', name: 'str',  # pylint: disable=unused-argument
                  obj: 'Any', options: 'dict[str, Any]', lines: 'list[str]') -> 'None':  # pylint: disable=unused-argument
    if what == 'module' and 'zlogging' in name:
        module = sys.modules.get(name)
        if module is None:
            return

        logger.info('reloading module: %s', name)
        typing.TYPE_CHECKING = True
        importlib.reload(module)
        logger.info('reloaded module: %s', name)


def setup(app: 'Sphinx') -> 'None':  # pylint: disable=unused-argument
    app.connect('autodoc-process-docstring', reload_module)

    # typing.TYPE_CHECKING = True
    # for name, module in sys.modules.copy().items():
    #     if 'zlogging' not in name:
    #         continue

    #     logger.info('reloading module: %s', name)
    #     importlib.reload(module)
    #     logger.info('reloaded module: %s', name)
