from .wp_item import WPItem


class Plugin(WPItem):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb"""

        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 or 0 info if pluging trigerred warning"""
        return ["Plugin: {}".format(info) for info in super().get_infos()]

    def get_warnings(self):
        """Return plugin warnings"""
        # Adds plugin prefix on all warnings except vulns
        return [
            "{}{}".format(
                "Plugin: " if "Vulnerability" not in warning.splitlines()[0] else "",
                warning,
            )
            for warning in super().get_warnings()
        ]

    def get_name(self):
        return "Plugin: {}".format(self.slug)
