from .finding import _Finding


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

        super().__init__(data, *args, **kwargs)
        self.url = self.data.get("url", None)
        self.to_s = self.data.get("to_s", None)
        self.type = self.data.get("type", None)

    def _get_infos(self):
        """Return 1 info. First line of info string is the to_s string or the finding type. Complete references links too."""
        info = ""
        if self.to_s != self.url:
            info += self.to_s
        else:
            if self.type:
                if self.url:
                    info += "{}: {}".format(self.type.title(), self.url)
                else:
                    info += self.type
        if self.url and self.url not in info:
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
