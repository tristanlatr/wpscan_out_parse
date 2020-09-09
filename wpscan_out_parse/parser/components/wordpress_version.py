from .finding import _CoreFinding


class WordPressVersion(_CoreFinding):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb"""

        super().__init__(data, *args, **kwargs)
        self.number = self.data.get("number", None)
        self.release_date = self.data.get("release_date", None)
        self.status = self.data.get("status", None)

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
        return "{}".format(len(self.vulnerabilities))

    def get_name(self):
        return "WordPress {} {}".format(
            self.get_version(),
            "({})".format(self.release_date)
            if self.release_date and self.number
            else "",
        )
