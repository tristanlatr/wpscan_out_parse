from .finding import _CoreFindingNoVersion


class NotFullyConfigured(_CoreFindingNoVersion):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb"""

        super().__init__(data, *args, **kwargs)
        self.not_fully_configured = self.data

    def get_alerts(self):
        """Return 1 alert"""
        return ["Wordpress: {}".format(self.not_fully_configured)]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Not fully configured"
