from typing import Any, Dict, Sequence
from ...base import Component


class VulnAPI(Component):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb"""

        super().__init__(data, *args, **kwargs)

        self.http_error: str = self.data.get("http_error", None)
        self.error: str = self.data.get("error", None)

        self.plan: str = self.data.get("plan", None)
        self.requests_done_during_scan: int = self.data.get(
            "requests_done_during_scan", None
        )
        self.requests_remaining: int = self.data.get("requests_remaining", None)

    def get_infos(self) -> Sequence[str]:
        """Return 1 WPVulnDB info"""
        info = "WPVulnDB API"
        info += "\nPlan: {}".format(self.plan)
        info += "\nRequests: {} done during scan, {} remaining".format(
            self.requests_done_during_scan, self.requests_remaining
        )
        return [info]

    def get_warnings(self) -> Sequence[str]:
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

    def get_alerts(self) -> Sequence[str]:
        """Return empty list"""
        return []
