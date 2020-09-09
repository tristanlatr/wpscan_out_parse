import argparse
import json
import copy
import traceback
from . import VERSION
from .formatter import format_results
from .parser import parse_results_from_file
from .parser.results import _WPScanResults


class WPScanOutParseCLI:
    def __init__(self):
        """Load all config values as object properties"""

        exit_code = 0
        self.__dict__.update(vars(self.parse_args()))

        if self.version:
            self.print_version()
            exit(0)

        # Throw config errors
        if not self.wpscan_output_file:
            results = _WPScanResults()
            results["error"] = "Please provide WPScan output file to parse."
            print(format_results(results, format=self.format))
            exit(1)

        if self.summary and self.no_summary:
            results = _WPScanResults()
            results["error"] = "Incompatible options --summary and --no_summary"
            print(format_results(results, format=self.format))
            exit(1)

        if self.inline and self.format != "cli":
            results = _WPScanResults()
            results[
                "error"
            ] = "Incompatible options --inline and --format {}. You must use 'cli' format".format(
                self.format
            )
            print(format_results(results, format=self.format))
            exit(1)

        # Call parse_results_from_file()
        try:
            results = parse_results_from_file(
                self.wpscan_output_file, self.false_positive, self.show_all
            )
        except Exception:
            results = _WPScanResults()
            results["error"] = traceback.format_exc()
            print(format_results(results, format=self.format))
            exit(1)

        # Exit code determination based on the number of alerts, warnings and error
        if len(results["alerts"]) > 0:
            exit_code = 5
        elif len(results["warnings"]) > 0:
            exit_code = 6
        if results["error"]:
            if "WPScan failed" in results["error"]:
                exit_code = 4
            else:
                exit_code = 1

        # Delete infos and warnings if asked
        if self.no_infos:
            results["infos"] = None
        if self.no_warnings:
            results["infos"] = None
            results["warnings"] = None

        if not self.inline:

            if self.summary:
                results["alerts"] = None
                results["warnings"] = None
                results["infos"] = None
            if self.no_summary:
                results["summary"] = None

            # Print infos if any
            output = format_results(results, format=self.format, nocolor=self.no_color)
            if output:
                print(output)
        else:
            # Print only line
            print(results["summary"]["line"])

        exit(exit_code)

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(
            description="""wpscan_out_parse is a Python parser for WPScan output files (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.""",
            prog="wpscan_out_parse",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            usage="python3 -m wpscan_out_parse [Options] <File path>",
        )

        parser.add_argument(
            "wpscan_output_file",
            help="WPScan output file to parse. ",
            metavar="<File path>",
            type=str,
            nargs="?",
        )
        parser.add_argument(
            "--format",
            metavar="<Format>",
            help='output format, choices are: "cli", "html", "json"',
            choices=["cli", "html", "json"],
            default="cli",
        )
        parser.add_argument(
            "--summary",
            action="store_true",
            help="display ony the summary of issues per component. ",
        )
        parser.add_argument(
            "--inline",
            action="store_true",
            help='display only one line like: "WPScan result summary: alerts={}, warnings={}, infos={}, error={}". ',
        )
        parser.add_argument(
            "--no_warnings",
            action="store_true",
            help="do not display warnings, only summary and alerts. Implies --no_infos. ",
        )
        parser.add_argument(
            "--no_infos",
            action="store_true",
            help="do not display informations and findinds. ",
        )
        parser.add_argument(
            "--no_summary",
            action="store_true",
            help="do not display the summary of issues. ",
        )
        parser.add_argument(
            "--show_all",
            action="store_true",
            help="show all findings details (found by, confidence, confirmed by). ",
        )
        parser.add_argument(
            "--false_positive",
            metavar="String",
            help='consider all matching messages as infos and add "[False positive]" prefix. ',
            nargs="+",
            default=None,
        )
        parser.add_argument(
            "--no_color",
            action="store_true",
            help="do not colorize output. ",
        )
        parser.add_argument(
            "--version",
            action="store_true",
            help="print wpscan_out_parse version and exit. ",
        )
        return parser.parse_args()

    def print_version(self):
        print("wpscan_out_parse version {}".format(VERSION))


def main():
    WPScanOutParseCLI()


if __name__ == "__main__":
    main()
