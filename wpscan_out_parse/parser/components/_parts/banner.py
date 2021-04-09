from typing import Any, Dict, Sequence, List
from ...base import Component


class Banner(Component):
    def __init__(self, data: Dict[str, Any], *args: Any, **kwargs: Any):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb"""

        super().__init__(data, *args, **kwargs)

        self.description:str = self.data.get("description", None)
        self.version:str = self.data.get("version", None)
        self.authors:List[str] = self.data.get("authors", None)
        self.sponsor:str = self.data.get("sponsor", None) or self.data.get(
            "sponsored_by", None
        )

    def get_infos(self)-> Sequence[str]:
        info = "Scanned with {}".format(self.description)
        info += "\nVersion: {}".format(self.version)
        if self.show_all_details:
            info += "\nAuthors: {}".format(", ".join(self.authors))
            if self.sponsor:
                info += "\nSponsor: {}".format(self.sponsor)

        return [info]

    def get_warnings(self)-> Sequence[str]:
        """Return empty list"""
        return []

    def get_alerts(self)-> Sequence[str]:
        """Return empty list"""
        return []
