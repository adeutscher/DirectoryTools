#!/usr/bin/env python

import sys,os
from setuptools import setup

_top_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_top_dir, "lib"))

import DirectoryTools, DirectoryToolsSchemas, DirectoryToolsIndexes

del sys.path[0]

setup(name="DirectoryTools",
    version=DirectoryTools.__version__,
    description="A collection of methods for performing LDAP operations more conveniently.",
    keywords='ldap python',
    author='Alan Deutscher',
    author_email='alan@gadgeteering.ca',
    maintainer='Alan Deutscher',
    maintainer_email='alan@gadgeteering.ca',
    py_modules=["DirectoryTools","DirectoryToolsExceptions","DirectoryToolsIndexes","DirectoryToolsSchemas"],
    package_dir={"":"lib"},
    install_requires = ['python-ldap'],
    include_package_data=True,
    zip_safe=False
)
