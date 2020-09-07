#! /usr/bin/env python3
#
# WPScan output parser
#
# Authors: Florian Roth, Tristan Landès
# Summary design from Lukas Pustina (lukaspustina)
#
# DISCLAIMER - USE AT YOUR OWN RISK.

# Parse know vulnerabilities
# Parse vulnerability data and make more human readable.
# NOTE: You need an API token for the WPVulnDB vulnerability data.

# """
# All the WPScan fields for the JSON output in the views/json folders at:

# https://github.com/wpscanteam/CMSScanner/tree/master/app/views/json
# https://github.com/wpscanteam/wpscan/tree/master/app/views/json

# Here are some other inspirational ressources found about parsing wpscan json

# Generates a nice table output (Rust code)
#     https://github.com/lukaspustina/wpscan-analyze

# Python parser (do not parse for vulnerable theme or outdated warnings)
#     https://github.com/aaronweaver/AppSecPipeline/blob/master/tools/wpscan/parser.py

# Vulcan wpscan (Go)
#     https://github.com/adevinta/vulcan-checks/blob/master/cmd/vulcan-wpscan/wpscan.go
#     Great job listing all the fields

# Dradis ruby json Parser
#     https://github.com/dradis/dradis-wpscan/blob/master/lib/dradis/plugins/wpscan/importer.rb
#     No warnings neither but probably the clearest code

# Ressource Parsing CLI output:
#     List of all icons: https://github.com/wpscanteam/CMSScanner/blob/master/app/formatters/cli.rb
# """

import collections
from abc import ABC, abstractmethod

############ RESULTS CLASS ###########################

TEMPLATE_SCAN_RESULTS = {
    "infos": None,
    "warnings": None,
    "alerts": None,
    "summary": {"table": None, "line": None},
    "error": None,
}

TEMPLATE_SCAN_RESULTS_SUMMARY_ROW = {
    "Component": None,
    "Version": None,
    "Version State": None,
    "Vulnerabilities": None,
    "Status": None,
}


class _WPScanResults(collections.UserDict):
    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS.keys():
            if key not in self.data:
                self.data[key] = TEMPLATE_SCAN_RESULTS[key]


class _WPScanResultsSummaryRow(collections.UserDict):
    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS_SUMMARY_ROW.keys():
            if key not in self.data:
                self.data[key] = TEMPLATE_SCAN_RESULTS_SUMMARY_ROW[key]


########### BASE CLASS FOR CLI AND JSON PARSERS ##########


class _Component(ABC):
    """Base abstract class for all WPScan JSON and CLI components"""

    def __init__(self, data, false_positives_strings, show_all_details):

        if not data:
            data = {}
        self.data = data
        self.false_positives_strings = (
            false_positives_strings if false_positives_strings else []
        )
        self.show_all_details = False
        if show_all_details:
            self.show_all_details = True

    def is_false_positive(self, string):
        """False Positive Detection"""
        if not self.false_positives_strings:
            return False
        for fp_string in self.false_positives_strings:
            if fp_string in string:
                return True
        return False

    @abstractmethod
    def get_infos(self):
        """Return the component informations as a list of strings.  """
        pass

    @abstractmethod
    def get_warnings(self):
        """Return the component warnings as a list of strings.  """
        pass

    @abstractmethod
    def get_alerts(self):
        """Return the component alerts as a list of strings.  """
        pass


class _Parser(_Component):
    """Common class for CLI and JSON parsers.  """

    def __init__(self, data, *args, **kwargs):
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

    @abstractmethod
    def get_results(self):
        """Returns a dictionnary structure like:
        ```
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
        ```
        """
        pass

    def get_summary_line(self):
        """Return the summary string in one line"""
        line = (
            "WPScan result summary: alerts={}, warnings={}, infos={}, error={}".format(
                len(self.get_alerts()),
                len(self.get_warnings()),
                len(self.get_infos()),
                "1" if self.get_error() else "0",
            )
        )
        return line

    @abstractmethod
    def get_error(self):
        """ Return any error or None if no errors"""
        pass


############ WPSCAN JSON COMPONENTS DATA STRUCTURE ##########


class _CoreFinding(ABC):
    @abstractmethod
    def get_version(self):
        """Return the version number (as string)"""
        pass

    @abstractmethod
    def get_version_status(self):
        """Return a string in : "Outdated", "Latest", "NA", "Unknown" """
        pass

    @abstractmethod
    def get_vulnerabilities_string(self):
        """Return the number of vulnerabilities,   (as string)"""
        pass

    @abstractmethod
    def get_name(self):
        """Return the name of the finding.  """
        pass

    def get_status(self):
        """Return a string in : "Alert", "Warning", "Ok", "?" """
        try:
            return (
                "Alert"
                if self.get_alerts()
                else "Warning"
                if self.get_warnings()
                else "Ok"
                if self.get_version_status() == ""
                else "?"
            )
        except AttributeError:
            return None


class _CoreFindingNoVersion(_CoreFinding):
    def get_version(self):
        return "N/A"

    def get_version_status(self):
        return "N/A"

    def get_vulnerabilities_string(self):
        return ""


class _Finding(_Component):
    """ Generic WPScan finding"""

    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.found_by = data.get("found_by", None)
        self.confidence = data.get("confidence", None)
        self.interesting_entries = data.get("interesting_entries", None)
        self.confirmed_by = data.get("confirmed_by", None)
        self.vulnerabilities = [
            Vulnerability(vuln, *args, **kwargs)
            for vuln in data.get("vulnerabilities", [])
        ]
        self.vulnerabilities = [
            Vulnerability(vuln, *args, **kwargs)
            for vuln in data.get("vulnerabilities", [])
        ]
        self.references = data.get("references", None)

    def get_alerts(self):
        """Return list of vulnerabilities"""
        alerts = []
        for v in self.vulnerabilities:
            alerts.extend(v.get_alerts())
        return alerts

    def get_infos(self):
        """Return 1 info, only interesting entries. If no interesting entries: return an empty info string (to avoid errors)"""
        info = ""
        if self.interesting_entries:
            info += "Interesting entries: \n- {}".format(
                "\n- ".join(self.interesting_entries)
            )
            if self.show_all_details:
                info += "\n"
        if self.show_all_details:
            if self.found_by:
                info += "Found by: {} ".format(self.found_by)
            if self.confidence:
                info += "(confidence: {})".format(self.confidence)
            # info+="\n"
            if self.confirmed_by:
                info += "\nConfirmed by: "
                for entry in self.confirmed_by:
                    info += "\n- {} ".format(entry)
                    if self.confirmed_by[entry].get("confidence", None):
                        info += "(confidence: {})".format(
                            self.confirmed_by[entry]["confidence"]
                        )
                    if self.confirmed_by.get("interesting_entries", None):
                        info += "\n  Interesting entries: \n  - {}".format(
                            "\n  - ".join(self.confirmed_by.get("interesting_entries"))
                        )

        return [info]

    def get_references_str(self):
        """Process CVE, WPVulnDB, ExploitDB and Metasploit references to add links"""
        alert = ""
        if self.references:
            alert += "References: "
            for ref in self.references:
                if ref == "cve":
                    for cve in self.references[ref]:
                        alert += "\n- CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{}".format(
                            cve
                        )
                elif ref == "wpvulndb":
                    for wpvulndb in self.references[ref]:
                        alert += "\n- WPVulnDB: https://wpvulndb.com/vulnerabilities/{}".format(
                            wpvulndb
                        )
                elif ref == "metasploit":
                    for metasploit in self.references[ref]:
                        alert += "\n- Metasploit: https://www.rapid7.com/db/modules/{}".format(
                            metasploit
                        )
                elif ref == "exploitdb":
                    for exploitdb in self.references[ref]:
                        alert += "\n- ExploitDB: https://www.exploit-db.com/exploits/{}".format(
                            exploitdb
                        )
                elif ref == "packetstorm":
                    for packetstorm in self.references[ref]:
                        alert += "\n- Packetstorm: https://packetstormsecurity.com/files/{}".format(
                            packetstorm
                        )

                else:
                    for link in self.references[ref]:
                        alert += "\n- {}: {}".format(ref.title(), link)
        return alert


class Vulnerability(_Finding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.title = data.get("title", None)
        self.cvss = data.get("cvss", None)
        self.fixed_in = data.get("fixed_in", None)

    def get_alerts(self):
        """Return 1 alert. First line of alert string contain the vulnerability title. Process CVE, WPVulnDB, ExploitDB and Metasploit references to add links"""
        alert = "Vulnerability: {}".format(self.title)

        if self.cvss:
            alert += "\nCVSS: {}".format(self.cvss)
        if self.fixed_in:
            alert += "\nFixed in: {}".format(self.fixed_in)
        else:
            alert += "\nNo known fix"
        if self.references:
            alert += "\n{}".format(self.get_references_str())
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []


class InterestingFinding(_Finding):

    INTERESTING_FINDING_WARNING_STRINGS = [
        "Upload directory has listing enabled",
        "Registration is enabled",
        "Debug Log found",
        "codex.wordpress.org/Debugging_in_WordPress",
        "Fantastico list found",
        "www.acunetix.com/vulnerabilities/fantastico-fileslist/",
    ]

    INTERESTING_FINDING_ALERT_STRINGS = [
        "SQL Dump found",
        "Full Path Disclosure found",
        "www.owasp.org/index.php/Full_Path_Disclosure",
        "codex.wordpress.org/Resetting_Your_Password#Using_the_Emergency_Password_Reset_Script",
        "www.exploit-db.com/ghdb/3981/",
        "A backup directory has been found",
        "github.com/wpscanteam/wpscan/issues/422",
        "ThemeMakers migration file found",
        "packetstormsecurity.com/files/131957",
        "Search Replace DB script found",
        "interconnectit.com/products/search-and-replace-for-wordpress-databases/",
    ]

    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb
        Warnings and Alerts strings are from https://github.com/wpscanteam/wpscan/blob/master/app/models/interesting_finding.rb
        """
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.url = data.get("url", None)
        self.to_s = data.get("to_s", None)
        self.type = data.get("type", None)

    def _get_infos(self):
        """Return 1 info. First line of info string is the to_s string or the finding type. Complete references links too."""
        info = ""
        if self.to_s != self.url:
            info += self.to_s
        elif self.type:
            info += self.type.title()
        if self.url and self.url not in self.to_s:
            info += "\nURL: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0]:
            info += "\n{}".format(super().get_infos()[0])
        if self.references:
            info += "\n{}".format(self.get_references_str())
        return [info]

    def get_infos(self):
        """Return 1 info or 0 if finding is a warning or an alert"""
        return [
            info
            for info in self._get_infos()
            if not any(
                [
                    string in info
                    for string in self.INTERESTING_FINDING_WARNING_STRINGS
                    + self.INTERESTING_FINDING_ALERT_STRINGS
                ]
            )
        ]

    def get_warnings(self):
        """Return list of warnings if finding match warning string"""
        return [
            info
            for info in self._get_infos()
            if any(
                [string in info for string in self.INTERESTING_FINDING_WARNING_STRINGS]
            )
        ]

    def get_alerts(self):
        """Return list of alerts if finding match ALERT string"""
        return [
            info
            for info in self._get_infos()
            if any(
                [string in info for string in self.INTERESTING_FINDING_ALERT_STRINGS]
            )
        ]


class WordPressVersion(_Finding, _CoreFinding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.number = data.get("number", None)
        self.release_date = data.get("release_date", None)
        self.status = data.get("status", None)

    def _get_infos(self):
        """Return 1 info"""
        if self.number:
            info = "Wordpress version: {}".format(self.number)
            if self.status == "latest":
                info += " (up to date)"
            if self.release_date:
                info += "\nRelease Date: {}".format(self.release_date)
            # Not showing "Status: "
            # if self.status:
            #     info+="\nStatus: {}".format(self.status.title())
        else:
            info = "The WordPress version could not be detected"
        # If finding infos are present and show_all_details, add them
        if super().get_infos()[0] and self.show_all_details:
            info += "\n{}".format(super().get_infos()[0])
        return [info]

    def get_infos(self):
        """Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use get_warnings()"""
        if not self.get_warnings():
            return self._get_infos()
        else:
            return []

    def get_warnings(self):
        """Return 0 or 1 warning"""

        if self.status == "insecure":
            warning = "Outdated "
            warning += self._get_infos()[0]
            return [warning]
        else:
            return []

    def get_alerts(self):
        """Return Wordpress Version vulnerabilities"""
        return ["Wordpress {}".format(alert) for alert in super().get_alerts()]

    def get_version(self):
        """Return the version string or 'Unknown'"""
        return self.number if self.number else "Unknown"

    def get_version_status(self):
        if self.number:
            if self.status == "insecure":
                return "Outdated"
            elif self.status == "latest":
                return "Latest"
            else:
                return "Unknown"
        else:
            return "N/A"

    def get_vulnerabilities_string(self):
        return "{}".format(
            len(self.vulnerabilities) if self.get_version() != "Unknown" else "?"
        )

    def get_name(self):
        return "WordPress {} {}".format(
            self.get_version(),
            "({})".format(self.release_date)
            if self.release_date and self.number
            else "",
        )


class WPItemVersion(_Finding):
    def __init__(self, data, *args, **kwargs):
        """Themes, plugins and timthumbs Version. From:
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
        """
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.number = data.get("number", None)

    def get_alerts(self):
        """Return any item version vulnerabilities"""
        return super().get_alerts()

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return 0 or 1 info. No infos if version could not be recognized"""
        if self.number:
            info = "Version: {}".format(self.number)
            # If finding infos are present, add them
            if super().get_infos()[0] and self.show_all_details:
                info += "\n{}".format(super().get_infos()[0])
            return [info]
        else:
            return []

    def get_version(self):
        if self.get_infos():
            return self.number
        else:
            return "Unknown"


class WPItem(_Finding, _CoreFinding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.slug = data.get("slug", None)
        self.location = data.get("location", None)
        self.latest_version = data.get("latest_version", None)
        self.last_updated = data.get("last_updated", None)
        self.outdated = data.get("outdated", None)
        self.readme_url = data.get("readme_url", None)
        self.directory_listing = data.get("directory_listing", None)
        self.error_log_url = data.get("error_log_url", None)
        self.version = WPItemVersion(data.get("version", None), *args, **kwargs)

    def _get_warnings(self):
        """Return 0 or 1 warning. The warning can contain infos about oudated plugin, directory listing or accessible error log.
        First line of warning string is the plugin slug. Location also added as a reference."""
        # Test if there is issues
        issue_data = ""
        if self.outdated:
            issue_data += "\nThe version is out of date"
        if self.directory_listing:
            issue_data += "\nDirectory listing is enabled"
            issue_data += "\nLocation: {}".format(self.location)
        if self.error_log_url:
            issue_data += "\nAn error log file has been found: {}".format(
                self.error_log_url
            )

        if not issue_data:
            return []  # Return if no issues
        else:
            return [issue_data]

    def get_alerts(self):
        """Return list of know plugin or theme vulnerability. Empty list is returned if plugin version is unrecognized"""
        alerts = []
        if self.version.get_infos():
            alerts.extend(["{}".format(alert) for alert in super().get_alerts()])
            alerts.extend(["{}".format(alert) for alert in self.version.get_alerts()])
        return alerts

    def get_warnings(self):
        """Return plugin or theme warnings, if oudated plugin, directory listing, accessible error log and
        for all know vulnerabilities if plugin version could not be recognized.
        Adds a special text saying the version is unrecognized if that's the case"""
        warnings = []
        # Prepare warning string
        warning = self.slug if self.slug else str()
        # Get oudated theme warning
        if self._get_warnings():
            warning += self._get_warnings()[0]
        if warning:
            warning += "\n"
        # Get generic infos
        warning += self._get_infos()[0]
        # If vulns are found and the version is unrecognized
        if not self.version.get_infos() and super().get_alerts():
            # Adds a special text saying all vulns are listed
            warning += "\nAll known vulnerabilities are listed"
        # If vulns are found and the version is unrecognized or other issue like outdated version or directory listing enable
        if (
            not self.version.get_infos() and super().get_alerts()
        ) or self._get_warnings():
            warnings.append(warning)
        # If vulns are found and the version is unrecognized : add Potential vulns
        if not self.version.get_infos() and super().get_alerts():
            warnings.extend(
                ["Potential {}".format(warn) for warn in super().get_alerts()]
            )
            warnings.extend(
                ["Potential {}".format(warn) for warn in self.version.get_alerts()]
            )
        return warnings

    def _get_infos(self):
        """Return 1 info"""
        info = ""
        if self.show_all_details:
            if self.location:
                info += "Location: {}".format(self.location)
            if self.last_updated:
                info += "\nLast Updated: {}".format(self.last_updated)
        if self.readme_url:
            if info:
                info += "\n"
            info += "Readme: {}".format(self.readme_url)
        # If finding infos are present, add them
        if info:
            info += "\n"
        if super().get_infos()[0] and self.show_all_details:
            info += "{}\n".format(super().get_infos()[0])
        if self.version.get_infos():
            info += self.version.get_infos()[0]
            if self.version.number == self.latest_version:
                info += " (up to date)"
            elif self.latest_version:
                info += " (latest is {})".format(self.latest_version)
        else:
            info += "The version could not be determined"
            if self.latest_version:
                info += " (latest is {})".format(self.latest_version)

        return [info]

    def get_infos(self):
        """Return 0 or 1 info, no info if WPItem triggered warning, use get_warnings()"""
        if not self.get_warnings():
            return ["{}\n{}".format(self.slug, self._get_infos()[0])]
        else:
            return []

    def get_version(self):
        return self.version.get_version()

    def get_version_status(self):
        if self.version.get_infos():
            if self.outdated:
                return "Outdated"
            elif self.version.number == self.latest_version:
                return "Latest"
            else:
                return "Unknown"
        else:
            return "N/A"

    def get_vulnerabilities_string(self):
        return "{}{}".format(
            len(self.vulnerabilities),
            " (potential)"
            if not self.version.get_infos() and super().get_alerts()
            else "",
        )


class Plugin(WPItem):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 or 0 info if pluging trigerred warning"""
        return ["Plugin: {}".format(info) for info in super().get_infos()]

    def get_warnings(self):
        """Return plugin warnings"""
        # Adds plugin prefix on all warnings except vulns
        return [
            "{}{}".format(
                "Plugin: " if "Vulnerability" not in warning.splitlines()[0] else "",
                warning,
            )
            for warning in super().get_warnings()
        ]

    def get_name(self):
        return "Plugin: {}".format(self.slug)


class Theme(WPItem):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.style_url = data.get("style_url", None)
        self.style_name = data.get("style_name", None)
        self.style_uri = data.get("style_uri", None)
        self.description = data.get("description", None)
        self.author = data.get("author", None)
        self.author_uri = data.get("author_uri", None)
        self.template = data.get("template", None)
        self.license = data.get("license", None)
        self.license_uri = data.get("license_uri", None)
        self.tags = data.get("tags", None)
        self.text_domain = data.get("text_domain", None)
        self.parents = [
            Theme(theme, *args, **kwargs) for theme in data.get("parents", [])
        ]

    def _get_infos(self):
        """Return 1 info"""
        info = super()._get_infos()[0]

        if self.style_url:
            info += "\nStyle CSS: {}".format(self.style_url)
        if self.style_name and self.show_all_details:
            info += "\nStyle Name: {}".format(self.style_name)
        if self.style_uri:
            info += "\nStyle URI: {}".format(self.style_uri)
        if self.description and self.show_all_details:
            info += "\nDescription: {}".format(self.description)
        if self.author:
            info += "\nAuthor: {}".format(self.author)
            if self.author_uri:
                info += " - {}".format(self.author_uri)
        if self.show_all_details:
            if self.template:
                info += "\nTemplate: {}".format(self.template)
            if self.license:
                info += "\nLicense: {}".format(self.license)
            if self.license_uri:
                info += "\nLicense URI: {}".format(self.license_uri)
            if self.tags:
                info += "\nTags: {}".format(self.tags)
            if self.text_domain:
                info += "\nDomain: {}".format(self.text_domain)
            if self.parents:
                info += "\nParent Theme(s): {}".format(
                    ", ".join([p.slug for p in self.parents])
                )

        return [info]

    def get_infos(self):
        if super().get_infos():
            return ["Theme: {}".format(super().get_infos()[0])]
        else:
            return []

    def get_warnings(self):
        """Return theme warnings"""
        return [
            "{}{}".format(
                "Theme: " if "Vulnerability" not in warning.splitlines()[0] else "",
                warning,
            )
            for warning in super().get_warnings()
        ]

    def get_name(self):
        return "Theme: {}".format(self.slug)


class MainTheme(Theme):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 info"""
        return [
            "Main Theme: {}".format(info) for info in super(Theme, self).get_infos()
        ]

    def get_warnings(self):
        """Return Main Theme warnings"""
        return [
            "{}{}".format(
                "Main Theme: "
                if "Vulnerability" not in warning.splitlines()[0]
                else "",
                warning,
            )
            for warning in super(Theme, self).get_warnings()
        ]

    def get_name(self):
        return "Main Theme: {}".format(self.slug)


class Timthumb(_Finding, _CoreFinding):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.url = url
        self.version = WPItemVersion(data.get("version", None), *args, **kwargs)

    def get_infos(self):
        """Return 1 info"""
        info = "Timthumb: {}".format(self.url)
        # If finding infos are present and show_all_details, add them
        if super().get_infos()[0] and self.show_all_details:
            info += "\n{}".format(super().get_infos()[0])
        if self.version.get_infos():
            info += "\n{}".format(self.version.get_infos()[0])
        else:
            info += "\nThe version could not be determined"
        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return timthumb vulnerabilities"""
        return [
            "Timthumb {}".format(alert)
            for alert in super().get_alerts() + self.version.get_alerts()
        ]

    def get_version(self):
        return self.version.get_version()

    def get_version_status(self):
        if self.version.get_infos():
            return "?"
        else:
            return "N/A"

    def get_vulnerabilities_string(self):
        return "{}{}".format(
            len(self.vulnerabilities),
            " (potential)"
            if not self.version.get_infos() and super().get_alerts()
            else "",
        )

    def get_name(self):
        return "Timthumb"


class DBExport(_Finding, _CoreFindingNoVersion):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_alerts(self):
        """Return 1 DBExport alert"""
        alert = "Database Export: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert += "\n{}".format(super().get_infos()[0])
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Database Export"


class User(_Finding):
    def __init__(self, username, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
        And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
        """
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.username = username
        self.id = data.get("id", None)
        self.password = data.get("password", None)

    def get_infos(self):
        """Return 1 info"""
        info = "User Identified: {}".format(self.username)
        if self.id:
            info += "\nID: {}".format(self.id)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            info += "\n{}".format(super().get_infos()[0])
        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return 0 or 1 alert. Alert if password found. Used by PasswordAttack component"""
        if self.password:
            alert = "Username: {}".format(self.username)
            alert += "Password: {}".format(self.password)
            return [alert]
        else:
            return []


class PasswordAttack(_Component, _CoreFindingNoVersion):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.users = [User(user, data.get(user), *args, **kwargs) for user in data]

    def get_alerts(self):
        """Return Password Attack Valid Combinations Found alerts"""
        alerts = []
        for user in self.users:
            alert = "Password Attack Valid Combinations Found:"
            if user.get_alerts():
                alert += "\n{}".format(user.get_alerts()[0])
                alerts.append(alert)

        return alerts

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Password Attack: {} found".format(len(self.get_alerts()))


class NotFullyConfigured(_Component, _CoreFindingNoVersion):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.not_fully_configured = data

    def get_alerts(self):
        """Return 1 alert"""
        return ["Wordpress: {}".format(self.not_fully_configured)]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Noy fully configured"


class Media(_Finding):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_infos(self):
        """Return 1 Media info"""
        alert = "Media: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert += "\n{}".format(super().get_infos()[0])
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []


class ConfigBackup(_Finding, _CoreFindingNoVersion):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_alerts(self):
        """Return 1 Config Backup alert"""
        alert = "Config Backup: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert += "\n{}".format(super().get_infos()[0])
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Config backup"


class VulnAPI(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.http_error = data.get("http_error", None)
        self.error = data.get("error", None)

        self.plan = data.get("plan", None)
        self.requests_done_during_scan = data.get("requests_done_during_scan", None)
        self.requests_remaining = data.get("requests_remaining", None)

    def get_infos(self):
        """Return 1 WPVulnDB info"""
        info = "WPVulnDB API"
        info += "\nPlan: {}".format(self.plan)
        info += "\nRequests: {} done during scan, {} remaining".format(
            self.requests_done_during_scan, self.requests_remaining
        )
        return [info]

    def get_warnings(self):
        """Return 0 or 1 warning. VulnAPI error No WPVulnDB API Token given or HTTP errors"""
        warning = ""
        if self.http_error:
            warning += "HTTP Error: {}".format(self.http_error)
        if self.error:
            warning += self.error
        if warning:
            return [warning]
        else:
            return []

    def get_alerts(self):
        """Return empty list"""
        return []


class Banner(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.description = data.get("description", None)
        self.version = data.get("version", None)
        self.authors = data.get("authors", None)
        self.sponsor = data.get("sponsor", None) or data.get("sponsored_by", None)

    def get_infos(self):
        info = "Scanned with {}".format(self.description)
        info += "\nVersion: {}".format(self.version)
        if self.show_all_details:
            info += "\nAuthors: {}".format(", ".join(self.authors))
            if self.sponsor:
                info += "\nSponsor: {}".format(self.sponsor)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []


class ScanStarted(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.start_time = data.get("start_time", None)
        self.start_memory = data.get("start_memory", None)
        self.target_url = data.get("target_url", None)
        self.target_ip = data.get("target_ip", None)
        self.effective_url = data.get("effective_url", None)

    def get_infos(self):
        """Return 1 Scan Scanned info"""

        info = "Target URL: {}".format(self.target_url)
        info += "\nTarget IP: {}".format(self.target_ip)
        info += "\nEffective URL: {}".format(self.effective_url)
        if self.show_all_details:
            info += "\nStart Time: {}".format(self.start_time)
            info += "\nStart Memory: {}".format(self.start_memory)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []


class ScanFinished(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb"""
        if not data:
            data = {}
        super().__init__(data, *args, **kwargs)

        self.stop_time = data.get("stop_time", None)
        self.elapsed = data.get("elapsed", None)
        self.requests_done = data.get("requests_done", None)
        self.cached_requests = data.get("cached_requests", None)
        self.data_sent_humanised = data.get("data_sent_humanised", None)
        self.data_received_humanised = data.get("data_received_humanised", None)
        self.used_memory_humanised = data.get("used_memory_humanised", None)

    def get_infos(self):
        """Return 1 Scan Finished info"""

        info = "Scan duration: {} seconds".format(self.elapsed)
        if self.show_all_details:
            info += "\nStop Time: {}".format(self.stop_time)
            info += "\nRequests Done: {}".format(self.requests_done)
            info += "\nCached Requests: {}".format(self.cached_requests)
            info += "\nData Sent: {}".format(self.data_sent_humanised)
            info += "\nData Received: {}".format(self.data_received_humanised)
            info += "\nUsed Memory: {}".format(self.used_memory_humanised)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []
