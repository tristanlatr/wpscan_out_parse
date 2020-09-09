from .finding import _CoreFindingNoVersion
from .user import User


class PasswordAttack(_CoreFindingNoVersion):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb"""

        super().__init__(data, *args, **kwargs)

        self.users = [User(user, self.data.get(user), *args, **kwargs) for user in data]

    def get_alerts(self):
        """Return Password Attack Valid Combinations Found alerts"""
        alerts = []
        for user in self.users:
            alert = "Password Attack Valid Combinations Found:"
            if user.get_alerts():
                alert += "\n{}".format(user.get_alerts()[0])
                alerts.append(alert)

        return alerts

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return "Password Attack: {} found".format(len(self.get_alerts()))
