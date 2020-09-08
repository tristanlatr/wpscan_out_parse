from .theme import Theme


class MainTheme(Theme):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb"""

        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 info"""
        return [
            "Main Theme: {}".format(info) for info in super(Theme, self).get_infos()
        ]

    def get_warnings(self):
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

    def get_name(self):
        return "Main Theme: {}".format(self.slug)
