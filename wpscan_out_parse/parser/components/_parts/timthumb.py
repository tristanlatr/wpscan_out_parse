from itertools import chain
from typing import Any, Dict, Sequence
from .wp_item import WPItem


class Timthumb(WPItem):
    def __init__(self, url:str, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""

        super().__init__(data, *args, **kwargs)
        self.url:str = url

    def get_infos(self) -> Sequence[str]:
        """Return 0 or 1 info, no info if Timthumb triggered warning, use get_warnings()"""
        return [
            "Timthumb: {}\n{}".format(self.url, info) for info in super().get_infos()
        ]

    def get_warnings(self) -> Sequence[str]:
        """Returns warnings"""
        return [
            "Timthumb: {}\n{}".format(self.url, alert)
            for alert in chain(super().get_warnings(), self.version.get_alerts())
        ]

    def get_alerts(self) -> Sequence[str]:
        """Return timthumb vulnerabilities"""
        return [
            "Timthumb: {}\n{}".format(self.url, alert)
            for alert in chain(super().get_alerts(), self.version.get_alerts())
        ]

    def get_name(self) -> str:
        return "Timthumb"
