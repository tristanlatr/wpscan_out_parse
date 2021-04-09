from typing import Any, Dict, Sequence
from .theme import Theme


class MainTheme(Theme):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb"""

        super().__init__(data, *args, **kwargs)

    def get_infos(self)-> Sequence[str]:
        """Return 1 info"""
        return [
            "Main Theme: {}".format(info) for info in super(Theme, self).get_infos()
        ]

    def get_warnings(self)-> Sequence[str]:
        """Return Main Theme warnings"""
        return [
            "{}{}".format(
                "Main Theme: "
                if "Vulnerability" not in warning.splitlines()[0]
                else "",
                warning,
            )
            for warning in super(Theme, self).get_warnings()
        ]

    def get_name(self) -> str:
        return "Main Theme: {}".format(self.slug)
