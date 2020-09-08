from ..base import _Component


class ScanFinished(_Component):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb"""

        super().__init__(data, *args, **kwargs)

        self.stop_time = self.data.get("stop_time", None)
        self.elapsed = self.data.get("elapsed", None)
        self.requests_done = self.data.get("requests_done", None)
        self.cached_requests = self.data.get("cached_requests", None)
        self.data_sent_humanised = self.data.get("data_sent_humanised", None)
        self.data_received_humanised = self.data.get("data_received_humanised", None)
        self.used_memory_humanised = self.data.get("used_memory_humanised", None)

    def get_infos(self):
        """Return 1 Scan Finished info"""

        info = "Scan duration: {} seconds".format(self.elapsed)
        if self.show_all_details:
            info += "\nStop Time: {}".format(self.stop_time)
            info += "\nRequests Done: {}".format(self.requests_done)
            info += "\nCached Requests: {}".format(self.cached_requests)
            info += "\nData Sent: {}".format(self.data_sent_humanised)
            info += "\nData Received: {}".format(self.data_received_humanised)
            info += "\nUsed Memory: {}".format(self.used_memory_humanised)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []
