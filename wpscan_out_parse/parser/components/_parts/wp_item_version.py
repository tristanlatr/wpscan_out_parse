from typing import Any, Dict, Sequence
from .finding import Finding


class WPItemVersion(Finding):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """Themes, plugins and timthumbs Version. From:
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
        """

        super().__init__(data, *args, **kwargs)
        self.number: str = self.data.get("number", None)

    def get_alerts(self) -> Sequence[str]:
        """Return any item version vulnerabilities"""
        return super().get_alerts()

    def get_warnings(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_infos(self) -> Sequence[str]:
        """Return 0 or 1 info. No infos if version could not be recognized"""
        if self.number:
            info = "Version: {}".format(self.number)
            # If finding infos are present, add them
            super_infos = super().get_infos()
            if super_infos and all(super_infos) and self.show_all_details:
                info += "\n{}".format(next(iter(super_infos)))
            return [info]
        else:
            return []

    def get_version(self) -> str:
        if self.get_infos():
            return self.number
        else:
            return "Unknown"
