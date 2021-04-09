from typing import Any, Dict, Sequence
from .finding import Finding


class User(Finding):
    def __init__(self, username:str, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
        And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
        """

        super().__init__(data, *args, **kwargs)

        self.username:str = username
        self.id: int = self.data.get("id", None)
        self.password: str = self.data.get("password", None)

    def get_infos(self) -> Sequence[str]:
        """Return 1 info"""
        info = "User Identified: {}".format(self.username)
        if self.id:
            info += " (ID: {})".format(self.id)
        # If finding infos are present, add them
        super_infos = super().get_infos()
        if super_infos and all(super_infos) and self.show_all_details:
            info += "\n{}".format(next(iter(super_infos)))
        return [info]

    def get_warnings(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_alerts(self) -> Sequence[str]:
        """Return 0 or 1 alert. Alert if password found. Used by PasswordAttack component"""
        if self.password:
            alert = "Username: {}".format(self.username)
            alert += "Password: {}".format(self.password)
            return [alert]
        else:
            return []
