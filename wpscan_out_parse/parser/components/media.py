from .finding import _Finding


class Media(_Finding):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb"""

        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_infos(self):
        """Return 1 Media info"""
        alert = "Media: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert += "\n{}".format(super().get_infos()[0])
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []
