from typing import Any, Dict, Sequence
from .finding import _CoreFinding


class WordPressVersion(_CoreFinding):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb"""

        super().__init__(data, *args, **kwargs)
        self.number: str = self.data.get("number", None)
        self.release_date: str = self.data.get("release_date", None)
        self.status: str = self.data.get("status", None)

    def _get_infos(self) -> Sequence[str]:
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
        super_infos = super().get_infos()
        if super_infos and all(super_infos) and self.show_all_details:
            info += "\n{}".format(next(iter(super_infos)))
        return [info]

    def get_infos(self) -> Sequence[str]:
        """Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use get_warnings()"""
        if not self.get_warnings():
            return self._get_infos()
        else:
            return []

    def get_warnings(self) -> Sequence[str]:
        """Return 0 or 1 warning"""

        if self.status in ["insecure", "outdated"]:
            warning = "Outdated "
            warning += next(iter(self._get_infos()))
            return [warning]
        else:
            return []

    def get_alerts(self) -> Sequence[str]:
        """Return Wordpress Version vulnerabilities"""
        return ["Wordpress {}".format(alert) for alert in super().get_alerts()]

    def get_version(self) -> str:
        """Return the version string or 'Unknown'"""
        return self.number if self.number else "Unknown"

    def get_version_status(self) -> str:
        if self.number:
            if self.status in ["insecure", "outdated"]:
                return "Outdated"
            elif self.status == "latest":
                return "Latest"
            else:
                return "Unknown"
        else:
            return "N/A"

    def get_vulnerabilities_string(self) -> str:
        return "{}".format(len(self.vulnerabilities))

    def get_name(self) -> str:
        return "WordPress {} {}".format(
            self.get_version(),
            "({})".format(self.release_date)
            if self.release_date and self.number
            else "",
        )
