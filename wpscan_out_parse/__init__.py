"""
WPScan Output Parser Python library documentation.  
"""

__all__ = [
    "WPScanJsonParser",
    "WPScanCliParser",
    "parse_results_from_string",
    "parse_results_from_file",
    "format_results",
]

VERSION = "1.8.1"

###################### IMPORTS  ######################

from .parser.json_parser import WPScanJsonParser
from .parser.cli_parser import WPScanCliParser
from .parser import parse_results_from_string, parse_results_from_file
from .formatter import format_results
