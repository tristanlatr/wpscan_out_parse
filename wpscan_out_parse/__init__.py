"""
WPScan Output Parser Python library documentation.  
"""

__all__ = [
    "parse_results_from_string",
    "parse_results_from_file",
    "format_results",
    "WPScanCliParser",
    "WPScanJsonParser",
]

VERSION = "1.5"

###################### IMPORTS  ######################

from .parser import parse_results_from_string, parse_results_from_file
from .formatter import format_results
from .parser.cli_parser import WPScanCliParser
from .parser.json_parser import WPScanJsonParser
