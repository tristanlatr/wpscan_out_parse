from typing import Any, Dict, Sequence
from .finding import _CoreFindingNoVersion


class ConfigBackup(_CoreFindingNoVersion):
    def __init__(self, url: str, data: Dict[str, Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb"""

        super().__init__(data, *args, **kwargs)
        self.url: str = url

    def get_alerts(self) -> Sequence[str]:
        """Return 1 Config Backup alert"""
        alert = "Config Backup: {}".format(self.url)
        # If finding infos are present, add them
        super_infos = super().get_infos()
        if super_infos and all(super_infos) and self.show_all_details:
            alert += "\n{}".format(next(iter(super_infos)))
        return [alert]

    def get_warnings(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_infos(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_name(self) -> str:
        return "Config backup"
