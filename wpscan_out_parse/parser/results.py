############ RESULTS CLASS ###########################

from typing import Any, Dict


TEMPLATE_SCAN_RESULTS: Dict[str, Any] = {
    "infos": None,
    "warnings": None,
    "alerts": None,
    "summary": {"table": None, "line": None},
    "error": None,
}

TEMPLATE_SCAN_RESULTS_SUMMARY_ROW: Dict[str, Any] = {
    "Component": None,
    "Version": None,
    "Version State": None,
    "Vulnerabilities": None,
    "Status": None,
}


class WPScanResults(dict):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS.keys():
            if key not in self:
                self[key] = TEMPLATE_SCAN_RESULTS[key]


class WPScanResultsSummaryRow(dict):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS_SUMMARY_ROW.keys():
            if key not in self:
                self[key] = TEMPLATE_SCAN_RESULTS_SUMMARY_ROW[key]
