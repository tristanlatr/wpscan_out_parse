#! /usr/bin/env python3
from setuptools import setup, find_packages
import sys
if sys.version_info[0] < 3: 
    raise RuntimeError("Sorry, you must use Python 3")
# The directory containing this file
import pathlib
HERE = pathlib.Path(__file__).parent
# About the project
ABOUT = {}
exec((HERE / "wpscan_out_parse" / "__version__.py").read_text(), ABOUT)

# The text of the README file
README = (HERE / "README.md").read_text()
setup(
    name                =   'wpscan_out_parse',
    description         =   "wpscan_out_parse is a Python parser for WPScan output files (JSON and CLI). It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.",
    url                 =   'http://github.com/tristanlatr/wpscan_out_parse',
    maintainer          =   'tristanlatr',
    version             =   ABOUT['VERSION'],
    packages            =   find_packages(exclude=('test')), 
    entry_points        =   {'console_scripts': ['wpscan_out_parse = wpscan_out_parse.__main__:wpscan_out_parse_cli'],},
    classifiers         =   ["Programming Language :: Python :: 3"],
    license             =   'MIT',
    long_description    =   README,
    long_description_content_type   =   "text/markdown",
    install_requires    =   ['ansicolors']
)

# Generating docs with python3 -m pdoc wpscan_out_parse --html --force -o docs
