"""
WPScan Output Parser Python library documentation.  

The python module exposes helper methods and 
Parser objects to parse WPScan results as your convevnience.  

**Exemples**

Using helper method `parse_results_from_file`.  Return all results as a simple dictionnary.  

.. python::

    import pprint
    from wpscan_out_parse import parse_results_from_file

    results = parse_results_from_file('./test/output_files/wordpress_many_vuln.json')
    pprint.pprint(results)


Using `WPScanJsonParser` object.  

.. python::

    import json
    import pprint
    from wpscan_out_parse import WPScanJsonParser

    with open('./test/output_files/wordpress_one_vuln.json', 'r') as wpscan_out:
        parser = WPScanJsonParser(json.load(wpscan_out))
        pprint.pprint(parser.get_warnings())

"""

__all__ = [
    "WPScanJsonParser",
    "WPScanCliParser",
    "parse_results_from_string",
    "parse_results_from_file",
    "format_results",
]

###################### IMPORTS  ######################

from .parser._json_parser import WPScanJsonParser
from .parser._cli_parser import WPScanCliParser
from .parser import parse_results_from_string
from .parser import parse_results_from_file
from .formatter import format_results
