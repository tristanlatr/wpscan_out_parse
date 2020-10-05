#! /usr/bin/env python3
from setuptools import setup, find_packages
import sys
if sys.version_info[0] < 3: 
    raise RuntimeError("Sorry, you must use Python 3")
# The directory containing this file
import pathlib
HERE = pathlib.Path(__file__).parent
# Helper method that will parse wpscan_out_parse/__init__.py to extract config setup values
def parse_setup(key):
    part={}
    for line in WPWATCHER.splitlines():
        if key in line:
            exec(line, part)
            break
    return(part[key])
# Read and store wpscan_out_parse/__init__.py file
WPWATCHER = (HERE / "wpscan_out_parse" / "__init__.py").read_text()
# The text of the README file
README = (HERE / "README.md").read_text()
setup(
    name                =   'wpscan_out_parse',
    description         =   "wpscan_out_parse is a Python parser for WPScan output files (JSON and CLI). It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.",
    url                 =   'http://github.com/tristanlatr/wpscan_out_parse',
    maintainer          =   'tristanlatr',
    version             =   parse_setup('VERSION'),
    packages            =   find_packages(exclude=('test')), 
    entry_points        =   {'console_scripts': ['wpscan_out_parse = wpscan_out_parse.__main__:main'],},
    classifiers         =   ["Programming Language :: Python :: 3"],
    license             =   'MIT',
    long_description    =   README,
    long_description_content_type   =   "text/markdown",
    install_requires    =   ['ansicolors']
)

# Generating docs with python3 -m pdoc wpscan_out_parse --html --force -o docs