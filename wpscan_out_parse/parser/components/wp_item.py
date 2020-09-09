from .finding import _CoreFinding
from .wp_item_version import WPItemVersion


class WPItem(_CoreFinding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb"""

        super().__init__(data, *args, **kwargs)

        self.slug = self.data.get("slug", None)
        self.location = self.data.get("location", None)
        self.latest_version = self.data.get("latest_version", None)
        self.last_updated = self.data.get("last_updated", None)
        self.outdated = self.data.get("outdated", None)
        self.readme_url = self.data.get("readme_url", None)
        self.directory_listing = self.data.get("directory_listing", None)
        self.error_log_url = self.data.get("error_log_url", None)
        self.version = WPItemVersion(self.data.get("version", None), *args, **kwargs)

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
                val = "Outdated"
            elif self.version.number == self.latest_version:
                val = "Latest"
            else:
                val = "Unknown"
        else:
            val = "N/A"

        if val != "Latest":
            val += (
                " (latest is {})".format(self.latest_version)
                if self.latest_version
                else ""
            )

        return val

    def get_vulnerabilities_string(self):
        return "{}{}".format(
            len(self.vulnerabilities),
            " (potential)"
            if not self.version.get_infos() and super().get_alerts()
            else "",
        )
