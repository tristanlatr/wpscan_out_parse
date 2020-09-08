from ..base import _Component


class Banner(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb"""

        super().__init__(data, *args, **kwargs)

        self.description = self.data.get("description", None)
        self.version = self.data.get("version", None)
        self.authors = self.data.get("authors", None)
        self.sponsor = self.data.get("sponsor", None) or self.data.get(
            "sponsored_by", None
        )

    def get_infos(self):
        info = "Scanned with {}".format(self.description)
        info += "\nVersion: {}".format(self.version)
        if self.show_all_details:
            info += "\nAuthors: {}".format(", ".join(self.authors))
            if self.sponsor:
                info += "\nSponsor: {}".format(self.sponsor)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []
