from .finding import _Finding, _CoreFinding
from .wp_item_version import WPItemVersion


class Timthumb(_Finding, _CoreFinding):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""

        super().__init__(data, *args, **kwargs)
        self.url = url
        self.version = WPItemVersion(self.data.get("version", None), *args, **kwargs)

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

    def get_name(self):
        return "Timthumb"
