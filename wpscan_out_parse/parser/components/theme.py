from .wp_item import WPItem


class Theme(WPItem):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb"""

        super().__init__(data, *args, **kwargs)

        self.style_url = self.data.get("style_url", None)
        self.style_name = self.data.get("style_name", None)
        self.style_uri = self.data.get("style_uri", None)
        self.description = self.data.get("description", None)
        self.author = self.data.get("author", None)
        self.author_uri = self.data.get("author_uri", None)
        self.template = self.data.get("template", None)
        self.license = self.data.get("license", None)
        self.license_uri = self.data.get("license_uri", None)
        self.tags = self.data.get("tags", None)
        self.text_domain = self.data.get("text_domain", None)
        self.parents = [
            Theme(theme, *args, **kwargs) for theme in self.data.get("parents", [])
        ]

    def _get_infos(self):
        """Return 1 info"""
        info = super()._get_infos()[0]

        if self.style_url:
            info += "\nStyle CSS: {}".format(self.style_url)
        if self.style_name and self.show_all_details:
            info += "\nStyle Name: {}".format(self.style_name)
        if self.style_uri:
            info += "\nStyle URI: {}".format(self.style_uri)
        if self.description and self.show_all_details:
            info += "\nDescription: {}".format(self.description)
        if self.author:
            info += "\nAuthor: {}".format(self.author)
            if self.author_uri:
                info += " - {}".format(self.author_uri)
        if self.show_all_details:
            if self.template:
                info += "\nTemplate: {}".format(self.template)
            if self.license:
                info += "\nLicense: {}".format(self.license)
            if self.license_uri:
                info += "\nLicense URI: {}".format(self.license_uri)
            if self.tags:
                info += "\nTags: {}".format(self.tags)
            if self.text_domain:
                info += "\nDomain: {}".format(self.text_domain)
            if self.parents:
                info += "\nParent Theme(s): {}".format(
                    ", ".join([p.slug for p in self.parents])
                )

        return [info]

    def get_infos(self):
        if super().get_infos():
            return ["Theme: {}".format(super().get_infos()[0])]
        else:
            return []

    def get_warnings(self):
        """Return theme warnings"""
        return [
            "{}{}".format(
                "Theme: " if "Vulnerability" not in warning.splitlines()[0] else "",
                warning,
            )
            for warning in super().get_warnings()
        ]

    def get_name(self):
        return "Theme: {}".format(self.slug)
