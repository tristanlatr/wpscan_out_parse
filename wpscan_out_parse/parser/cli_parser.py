import re

from .base import _Parser
from .components import InterestingFinding
from .results import _WPScanResults

####################  CLI PARSER ######################


class WPScanCliParser(_Parser):
    """Main interface to parse WPScan CLI output.

    - wpscan_output: WPScan output as string.
    - false_positives_strings: List of false positive strings.

    """

    def __init__(self, wpscan_output, false_positives_strings=None):

        if not wpscan_output:
            wpscan_output = ""
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config = dict(
            false_positives_strings=false_positives_strings, show_all_details=False
        )
        super().__init__(wpscan_output, **parser_config)
        self.infos, self.warnings, self.alerts = self.parse_cli(wpscan_output)

    def get_infos(self):
        """ Return all the parsed infos"""
        return self.infos

    def get_warnings(self):
        """ Return all the parsed warnings"""
        return self.warnings

    def get_alerts(self):
        """ Return all the parsed alerts"""
        return self.alerts

    def _parse_cli_toogle(self, line, warning_on, alert_on):
        # Color parsing
        if "33m[!]" in line:
            warning_on = True
        elif "31m[!]" in line:
            alert_on = True
        # No color parsing Warnings string are hard coded here
        elif "[!]" in line and any(
            [
                m in line
                for m in [
                    "The version is out of date",
                    "No WPVulnDB API Token given",
                    "You can get a free API token",
                ]
            ]
        ):
            warning_on = True
        elif "[!]" in line:
            alert_on = True
        # Both method with color and no color apply supplementary proccessing
        # Warning for insecure Wordpress and based on interesting findings strings
        if any(
            string in line
            for string in ["Insecure"]
            + InterestingFinding.INTERESTING_FINDING_WARNING_STRINGS
        ):
            warning_on = True
        # Trigger alert based on interesting finding alert strings
        if any(
            string in line
            for string in InterestingFinding.INTERESTING_FINDING_ALERT_STRINGS
        ):
            alert_on = True
        # Lower voice of Vulnerabilities found but not plugin version
        if "The version could not be determined" in line and alert_on:
            alert_on = False
            warning_on = True
        return (warning_on, alert_on)

    def _ignore_false_positives(self, infos, warnings, alerts):
        """Process false positives"""
        for alert in warnings + alerts:
            if self.is_false_positive(alert):
                try:
                    alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append("[False positive]\n{}".format(alert))

        return infos, warnings, alerts

    def parse_cli(self, wpscan_output):
        """Parse the ( messages, warnings, alerts ) from WPScan CLI output string.
        Return results as tuple( messages, warnings, alerts )."""
        # Init scan messages
        (messages, warnings, alerts) = ([], [], [])
        # Init messages toogles
        warning_on, alert_on = False, False
        message_lines = []
        current_message = ""

        # Every blank ("") line will be considered as a message separator
        for line in wpscan_output.splitlines() + [""]:

            # Parse all output lines and build infos, warnings and alerts
            line = line.strip()

            # Parse line
            warning_on, alert_on = self._parse_cli_toogle(line, warning_on, alert_on)

            # Remove colorization anyway after parsing
            line = re.sub(r"(\x1b|\[[0-9][0-9]?m)", "", line)
            # Append line to message. Handle the begin of the message case
            message_lines.append(line)

            # Build message
            current_message = "\n".join(
                [m for m in message_lines if m not in ["", "|"]]
            ).strip()

            # Message separator just a white line.
            # Only if the message if not empty.
            if line.strip() not in [""] or current_message.strip() == "":
                continue

            # End of the message

            # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
            if (alert_on or warning_on) and any(
                s in current_message
                for s in ["vulnerabilities identified", "vulnerability identified"]
            ):
                messages_separated = []
                msg = []
                for l in message_lines + ["|"]:
                    if l.strip() == "|":
                        messages_separated.append(
                            "\n".join([m for m in msg if m not in ["", "|"]])
                        )
                        msg = []
                    msg.append(l)

                # Append Vulnerabilities messages to ALERTS and other infos in one message
                vulnerabilities = [
                    m for m in messages_separated if "| [!] Title" in m.splitlines()[0]
                ]

                # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
                plugin_infos = "\n".join(
                    [
                        m
                        for m in messages_separated
                        if "| [!] Title" not in m.splitlines()[0]
                    ]
                )

                if (
                    len([v for v in vulnerabilities if not self.is_false_positive(v)])
                    > 0
                    and "The version could not be determined" in plugin_infos
                ):
                    warnings.append(
                        plugin_infos + "\nAll known vulnerabilities are listed"
                    )
                else:
                    messages.append(plugin_infos)

                if alert_on:
                    alerts.extend(vulnerabilities)
                elif warning_on:
                    warnings.extend(vulnerabilities)

            elif warning_on:
                warnings.append(current_message)
            else:
                messages.append(current_message)
            message_lines = []
            current_message = ""
            # Reset Toogle Warning/Alert
            warning_on, alert_on = False, False

        return self._ignore_false_positives(messages, warnings, alerts)

    def get_error(self):
        if "Scan Aborted" in self.data:
            return "WPScan failed: {}".format(
                "\n".join(
                    line for line in self.data.splitlines() if "Scan Aborted" in line
                )
            )
        else:
            return None

    def get_results(self):
        """
        Returns a dictionnary structure like:
        ```
        {
        'infos':[],
        'warnings':[],
        'alerts':[],
        'summary':{
            'table':None,
            'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
            },
        'error':None
        }
        ```
        """
        results = _WPScanResults()
        results["infos"] = self.get_infos()
        results["warnings"] = self.get_warnings()
        results["alerts"] = self.get_alerts()
        results["summary"]["line"] = self.get_summary_line()
        results["error"] = self.get_error()
        return dict(results)
