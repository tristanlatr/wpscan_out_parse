from .finding import _Finding


class WPItemVersion(_Finding):
    def __init__(self, data, *args, **kwargs):
        """Themes, plugins and timthumbs Version. From:
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
        """

        super().__init__(data, *args, **kwargs)
        self.number = self.data.get("number", None)

    def get_alerts(self):
        """Return any item version vulnerabilities"""
        return super().get_alerts()

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return 0 or 1 info. No infos if version could not be recognized"""
        if self.number:
            info = "Version: {}".format(self.number)
            # If finding infos are present, add them
            if super().get_infos()[0] and self.show_all_details:
                info += "\n{}".format(super().get_infos()[0])
            return [info]
        else:
            return []

    def get_version(self):
        if self.get_infos():
            return self.number
        else:
            return "Unknown"
