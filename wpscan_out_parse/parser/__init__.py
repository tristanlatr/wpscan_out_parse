import json

from .json_parser import WPScanJsonParser
from .cli_parser import WPScanCliParser

####################### INTERFACE METHODS ####################


def parse_results_from_string(
    wpscan_output_string, false_positives_strings=None, show_all_details=False
):
    """Parse any WPScan output string.

    - wpscan_output_string: WPScan output as string
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.

    Return the results as dict object"""
    try:
        data = json.loads(wpscan_output_string)
    except ValueError:
        parser = WPScanCliParser(wpscan_output_string, false_positives_strings)
    else:
        parser = WPScanJsonParser(data, false_positives_strings, show_all_details)
    return parser.get_results()


def parse_results_from_file(
    wpscan_output_file, false_positives_strings=None, show_all_details=False
):
    """Parse any WPScan output file.

    - wpscan_output_file: Path to WPScan output file
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.

     Return the results as dict object"""
    with open(wpscan_output_file, "r", encoding="utf-8") as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(
            wpscan_out_string,
            false_positives_strings=false_positives_strings,
            show_all_details=show_all_details,
        )

    return results
