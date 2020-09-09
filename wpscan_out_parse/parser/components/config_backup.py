from .finding import _CoreFindingNoVersion


class ConfigBackup(_CoreFindingNoVersion):
    def __init__(self, url, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb"""

        super().__init__(data, *args, **kwargs)
        self.url = url

    def get_alerts(self):
        """Return 1 Config Backup alert"""
        alert = "Config Backup: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert += "\n{}".format(super().get_infos()[0])
        return [alert]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Config backup"
