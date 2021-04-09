from typing import Any, Dict, Sequence
from .finding import _CoreFindingNoVersion


class NotFullyConfigured(_CoreFindingNoVersion):
    def __init__(self, data:Dict[str, Any], *args: Any, **kwargs: Any):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb"""

        super().__init__(data, *args, **kwargs)
        self.not_fully_configured:str = self.data.get("not_fully_configured", None)

    def get_alerts(self)-> Sequence[str]:
        """Return 1 alert"""
        return ["Wordpress: {}".format(self.not_fully_configured)]

    def get_warnings(self)-> Sequence[str]:
        """Return empty list"""
        return []

    def get_infos(self)-> Sequence[str]:
        """Return empty list"""
        return []

    def get_name(self) -> str:
        return "Not fully configured"
