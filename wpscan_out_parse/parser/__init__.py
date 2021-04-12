import json
from typing import Any, Dict, Sequence, Optional

from .base import Parser
from .results import WPScanResults
from ._json_parser import WPScanJsonParser
from ._cli_parser import WPScanCliParser

####################### INTERFACE METHODS ####################


def parse_results_from_string(
    wpscan_output_string: str, 
    false_positives_strings:Optional[Sequence[str]]=None, 
    show_all_details:bool=False
) -> WPScanResults:
    """Parse any WPScan output string.

    - wpscan_output_string: WPScan output as string
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.

    Return the results as dict object like
    
    ::
        
            {
            'infos':[],
            'warnings':[],
            'alerts':[],
            'summary':{
                'table':[
                    {
                        'Component': None,
                        'Version': None,
                        'Version State': None,
                        'Vulnerabilities': None,
                        'Status': None
                    },
                    ...
                ],
                'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
                },
            'error':None
            }
    
    (summary table is only parsed for JSON files)
    """
    parser: Parser
    try:
        data = json.loads(wpscan_output_string)
    except ValueError:
        parser = WPScanCliParser(wpscan_output_string, false_positives_strings)
    else:
        parser = WPScanJsonParser(data, false_positives_strings, show_all_details)
    return parser.get_results()


def parse_results_from_file(
    wpscan_output_file: str, 
    false_positives_strings:Optional[Sequence[str]]=None, 
    show_all_details:bool=False
) -> WPScanResults:
    """Parse any WPScan output file.

    - wpscan_output_file: Path to WPScan output file
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.

    Return the results as dict object. 
    
    See `parse_results_from_string`. """
    with open(wpscan_output_file, "r", encoding="utf-8") as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(
            wpscan_out_string,
            false_positives_strings=false_positives_strings,
            show_all_details=show_all_details,
        )

    return results
