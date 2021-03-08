"""
runas
=====

Execute a command as administrator

"""

from setuptools import setup, find_namespace_packages


NAME = "runas"
VERSION = "0.0.1"
DESCRIPTION = "run commands as administrator"
AUTHOR = "Michael Reithinger"
URL = "http://github.com/kochelmonster/runas/"
LICENSE = "BSD"
KEYWORDS = "sudo runas"
CLASSIFIERS = [
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: BSD License"
]


setup(name=NAME,
      version=VERSION,
      author=AUTHOR,
      url=URL,
      description=DESCRIPTION,
      long_description=__doc__,
      keywords=KEYWORDS,
      package_dir={'': 'src'},
      packages=find_namespace_packages(where="src"),
      license=LICENSE,
      classifiers=CLASSIFIERS,
     )
