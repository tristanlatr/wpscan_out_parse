from .finding import _Finding


class User(_Finding):
    def __init__(self, username, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
        And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
        """

        super().__init__(data, *args, **kwargs)

        self.username = username
        self.id = self.data.get("id", None)
        self.password = self.data.get("password", None)

    def get_infos(self):
        """Return 1 info"""
        info = "User Identified: {}".format(self.username)
        if self.id:
            info += " (ID: {})".format(self.id)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            info += "\n{}".format(super().get_infos()[0])
        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return 0 or 1 alert. Alert if password found. Used by PasswordAttack component"""
        if self.password:
            alert = "Username: {}".format(self.username)
            alert += "Password: {}".format(self.password)
            return [alert]
        else:
            return []
