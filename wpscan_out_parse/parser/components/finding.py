from abc import ABC, abstractmethod

from ..base import _Component


class _Finding(_Component):
    """ Generic WPScan finding"""

    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""

        super().__init__(data, *args, **kwargs)

        self.found_by = self.data.get("found_by", None)
        self.confidence = self.data.get("confidence", None)
        self.interesting_entries = self.data.get("interesting_entries", None)
        self.confirmed_by = self.data.get("confirmed_by", None)
        self.vulnerabilities = [
            Vulnerability(vuln, *args, **kwargs)
            for vuln in self.data.get("vulnerabilities", [])
        ]
        self.references = self.data.get("references", None)

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


class _CoreFinding(ABC):
    @abstractmethod
    def get_version(self):
        """Return the version number (as string) or "Unknown" or "" if not applicable. """
        pass

    @abstractmethod
    def get_version_status(self):
        """Return a string in : "Outdated", "Latest", "Unknown" or "" if not applicable.  """
        pass

    @abstractmethod
    def get_vulnerabilities_string(self):
        """Return the number of vulnerabilities (as string) with indications if need be. """
        pass

    @abstractmethod
    def get_name(self):
        """Return the name of the finding. """
        pass

    def get_status(self):
        """Return a string in : "Alert", "Warning", "Ok", "Unknown" """
        try:
            return (
                "Alert"
                if self.get_alerts()
                else "Warning"
                if self.get_warnings()
                else "Ok"
                if self.get_version_status() == "Latest"
                else "Unknown"
            )
        except AttributeError:
            return None


class _CoreFindingNoVersion(_CoreFinding):
    def get_version(self):
        """ Returns empty string"""
        return ""

    def get_version_status(self):
        """ Returns empty string"""
        return ""

    def get_vulnerabilities_string(self):
        """ Returns empty string"""
        return ""


# Class Vulnerability moved with Finding to avoid circular imorts errors
class Vulnerability(_Finding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""

        super().__init__(data, *args, **kwargs)

        self.title = self.data.get("title", None)
        self.cvss = self.data.get("cvss", None)
        self.fixed_in = self.data.get("fixed_in", None)

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
