import argparse
import json
import copy
import traceback
from . import VERSION
from .formatter import format_results
from .parser import parse_results_from_file, WPScanResults

class WPScanOutParse():

    def __init__(self):
        """Load all config values as object properties"""

        self.__dict__.update(vars(self.parse_args()))

        if self.version:
            self.print_version()
            exit(0)

        # Throw config errors
        if not self.wpscan_output_file:
            results=WPScanResults()
            results['error']="Please provide WPScan output file to parse."
            print(format_results(results, format=self.format))
            exit(1)
             
        if self.summary and self.no_summary:
            results=WPScanResults()
            results['error']="Incompatible options --summary and --no_summary"
            print(format_results(results, format=self.format))
            exit(1)

        if self.alerts and self.summary:
            results=WPScanResults()
            results['error']="Incompatible options --summary and --alerts"
            print(format_results(results, format=self.format))
            exit(1)

        if self.inline and self.format != 'cli':
            results=WPScanResults()
            results['error']="Incompatible options --inline and --format {}. You must use 'cli' format".format(self.format)
            print(format_results(results, format=self.format))
            exit(1)

        exit_code=0
        try:
            results=parse_results_from_file(self.wpscan_output_file, self.false_positive, self.show_all)
        except Exception:
            results=WPScanResults()
            results['error']=traceback.format_exc()
            print(format_results(results, format=self.format))
            exit(1)

        if len(results['alerts'])>0:
                exit_code = 5  
        elif len(results['warnings'])>0:
            exit_code = 6
        if results['error'] and 'WPScan failed' in results['error']:
            exit_code=4
        elif results['error']:
            exit_code=1

        if self.no_infos:
            results['infos']=None
        if self.no_warn:
            results['warnings']=None
        if self.alerts:
            results['infos']=None
            results['warnings']=None
        if self.summary:
            results['alerts']=None
            results['warnings']=None
            results['infos']=None
        if self.no_summary:
            results['summary']=None
        
        if self.alerts and not results['alerts'] and not results['error']:
            pass
        elif self.no_warn and ( not results['alerts'] and not results['error'] ):
            pass
        elif self.no_infos and ( not results['alerts'] and not results['warnings'] and not results['error'] ):
            pass
        else:
            if not self.inline:
                print(format_results(results, format=self.format))
            else:
                print(results['summary']['line'])
        
        exit(exit_code)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(description="""wpscan_out_parse is a Python parser for WPScan output files (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.""", prog='wpscan_out_parse', formatter_class=argparse.RawDescriptionHelpFormatter, usage='python3 -m wpscan_out_parse [Options] <File path>')

        parser.add_argument('wpscan_output_file', help='WPScan output file to parse. ', metavar='<File path>', type=str, nargs='?')
        parser.add_argument('--format', metavar='<Format>', help='output format, choices are: "cli", "html", "json"', choices=['cli', 'html', 'json'], default='cli')
        parser.add_argument('--alerts', action='store_true', help='display only alerts and summary. Implies --no_warnings. ')
        parser.add_argument('--summary', action='store_true', help='display ony the summary of issues per component. ')
        parser.add_argument('--inline', action='store_true', help='display only one line like: "WPScan result summary: alerts={}, warnings={}, ok={}". ')
        parser.add_argument('--no_warn', action='store_true', help='do not display warnings, only summary and alerts. Implies --no_infos. ')
        parser.add_argument('--no_infos', action='store_true', help='do not display informations and findinds. ')
        parser.add_argument('--no_summary', action='store_true', help='do not display the summary of issues. ')
        parser.add_argument('--show_all', action='store_true', help='show all findings details (found by, confidence, confirmed by). ')
        parser.add_argument('--false_positive', metavar='String', help='consider all matching messages as infos and add "[False positive]" prefix. ', nargs='+', default=None)
        parser.add_argument('--version', action='store_true', help='print wpscan_out_parse version and exit. ')
        return parser.parse_args()

    def print_version(self):
        print('wpscan_out_parse version {}'.format(VERSION))

if __name__ == '__main__':
    WPScanOutParse()
