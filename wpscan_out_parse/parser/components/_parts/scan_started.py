from typing import Any, Dict, Sequence
from ...base import Component


class ScanStarted(Component):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb"""

        super().__init__(data, *args, **kwargs)

        self.start_time = self.data.get("start_time", None)
        self.start_memory = self.data.get("start_memory", None)
        self.target_url = self.data.get("target_url", None)
        self.target_ip = self.data.get("target_ip", None)
        self.effective_url = self.data.get("effective_url", None)

    def get_infos(self) -> Sequence[str]:
        """Return 1 Scan Scanned info"""

        info = "Target URL: {}".format(self.target_url)
        info += "\nTarget IP: {}".format(self.target_ip)
        info += "\nEffective URL: {}".format(self.effective_url)
        if self.show_all_details:
            info += "\nStart Time: {}".format(self.start_time)
            info += "\nStart Memory: {}".format(self.start_memory)

        return [info]

    def get_warnings(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_alerts(self) -> Sequence[str]:
        """Return empty list"""
        return []
