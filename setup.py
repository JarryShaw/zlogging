# -*- coding: utf-8 -*-
"""Bro/Zeek logging framework for Python."""

# version string
__version__ = '0.1.1'

with open('README.rst') as file:
    long_description = file.read()

# setup attributes
attrs = dict(
    name='zlogging',
    version=__version__,
    description=__doc__,
    long_description=long_description,
    author='Jarry Shaw',
    author_email='jarryshaw@icloud.com',
    maintainer='Jarry Shaw',
    maintainer_email='jarryshaw@icloud.com',
    url='https://github.com/JarryShaw/zlogging',
    download_url='https://github.com/JarryShaw/zlogging/archive/v%s.tar.gz' % __version__,
    # py_modules,
    packages=['zlogging'],
    # scripts
    # ext_modules
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development',
        'Topic :: Utilities',
    ],
    # distclass
    # script_name
    # script_args
    # options
    license='BSD License',
    keywords=[
        'bro',
        'zeek',
        'logging',
    ],
    platforms=[
        'any'
    ],
    # cmdclass
    # data_files
    # package_dir
    # obsoletes
    # provides
    # requires
    # command_packages
    # command_options
    package_data={
        '': [
            'LICENSE',
            'README.md',
        ],
    },
    # include_package_data
    # libraries
    # headers
    # ext_package
    # include_dirs
    # password
    # fullname
    # long_description_content_type
    python_requires='>=3.6',
    # zip_safe,
    install_requires=[
        'typing-inspect',
        'typing_extensions',
        # version compatibility
        'dataclasses; python_version < "3.7"',
        'aenum; python_version < "3.7"',
    ],
    # entry_points,
    #extras_require={
    #    # version compatibility
    #    ':python_version == "3.6"': ['dataclasses', 'aenum'],
    #},
)

try:
    from setuptools import setup

    attrs.update(dict(
        include_package_data=True,  # type: ignore[dict-item]
        # libraries
        # headers
        # ext_package
        # include_dirs
        # password
        # fullname
        long_description_content_type='text/x-rst',
        # python_requires
        # zip_safe
    ))
except ImportError:
    from distutils.core import setup

# set-up script for pip distribution
setup(**attrs)
