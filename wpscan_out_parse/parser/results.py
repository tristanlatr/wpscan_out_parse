import collections

############ RESULTS CLASS ###########################

TEMPLATE_SCAN_RESULTS = {
    "infos": None,
    "warnings": None,
    "alerts": None,
    "summary": {"table": None, "line": None},
    "error": None,
}

TEMPLATE_SCAN_RESULTS_SUMMARY_ROW = {
    "Component": None,
    "Version": None,
    "Version State": None,
    "Vulnerabilities": None,
    "Status": None,
}


class _WPScanResults(collections.UserDict):
    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS.keys():
            if key not in self.data:
                self.data[key] = TEMPLATE_SCAN_RESULTS[key]


class _WPScanResultsSummaryRow(collections.UserDict):
    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS_SUMMARY_ROW.keys():
            if key not in self.data:
                self.data[key] = TEMPLATE_SCAN_RESULTS_SUMMARY_ROW[key]
