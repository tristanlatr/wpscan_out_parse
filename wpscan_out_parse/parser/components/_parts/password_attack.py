from typing import Any, Dict, Sequence
from .finding import _CoreFindingNoVersion
from .user import User


class PasswordAttack(_CoreFindingNoVersion):
    def __init__(self, data:Dict[str,Any], *args: Any, **kwargs: Any) -> None:
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb"""

        super().__init__(data, *args, **kwargs)

        self.users = [User(user, self.data[user], *args, **kwargs) for user in data]

    def get_alerts(self) -> Sequence[str]:
        """Return Password Attack Valid Combinations Found alerts"""
        alerts = []
        for user in self.users:
            alert = "Password Attack Valid Combinations Found:"
            if user.get_alerts():
                alert += "\n{}".format(next(iter(user.get_alerts())))
                alerts.append(alert)

        return alerts

    def get_warnings(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_infos(self) -> Sequence[str]:
        """Return empty list"""
        return []

    def get_name(self) -> str:
        return "Password Attack: {} found".format(len(self.users))
