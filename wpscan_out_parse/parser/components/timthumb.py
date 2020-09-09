from .wp_item import WPItem


class Timthumb(WPItem):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""

        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_infos(self):
        """Return 0 or 1 info, no info if Timthumb triggered warning, use get_warnings()"""
        return [
            "Timthumb: {}\n{}".format(self.url, info) for info in super().get_infos()
        ]

    def get_warnings(self):
        """Returns warnings"""
        return [
            "Timthumb: {}\n{}".format(self.url, alert)
            for alert in super().get_warnings() + self.version.get_alerts()
        ]

    def get_alerts(self):
        """Return timthumb vulnerabilities"""
        return [
            "Timthumb: {}\n{}".format(self.url, alert)
            for alert in super().get_alerts() + self.version.get_alerts()
        ]

    def get_name(self):
        return "Timthumb"
