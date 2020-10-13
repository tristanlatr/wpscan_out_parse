from .base import _Parser
from .components import (
    InterestingFinding,
    WordPressVersion,
    Plugin,
    MainTheme,
    Theme,
    Timthumb,
    DBExport,
    User,
    Media,
    ConfigBackup,
    VulnAPI,
    PasswordAttack,
    NotFullyConfigured,
    Banner,
    ScanStarted,
    ScanFinished,
)
from .components.finding import _CoreFinding
from .results import _WPScanResults, _WPScanResultsSummaryRow

#################### JSON PARSER ######################


class WPScanJsonParser(_Parser):
    """Main interface to parse WPScan JSON data

    - data: The JSON structure of the WPScan output.
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).

    Once instanciated, the following properties are accessible:

    - `version`
    - `main_theme`
    - `plugins` (list)
    - `themes` (list)
    - `interesting_findings` (list)
    - `timthumbs` (list)
    - `db_exports` (list)
    - `users` (list)
    - `medias` (list)
    - `config_backups` (list)
    - `password_attack`
    - `not_fully_configured`
    - `vuln_api`
    - `banner`
    - `scan_started`
    - `scan_finished`

    All objects implements `get_alerts()`, `get_warnings()` and `get_infos()`
    """

    def __init__(self, data, false_positives_strings=None, show_all_details=False):

        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config = dict(
            false_positives_strings=false_positives_strings,
            show_all_details=show_all_details,
        )
        super().__init__(data, **parser_config)
        self.components = []
        # Add WordPressVersion
        if "version" in self.data:
            self.version = WordPressVersion(self.data.get("version"), **parser_config)
        else:
            self.version = None
        # Add MainTheme
        if "main_theme" in self.data:
            self.main_theme = MainTheme(self.data.get("main_theme"), **parser_config)
        else:
            self.main_theme = None
        # Add Plugins
        if "plugins" in self.data:
            self.plugins = [
                Plugin(self.data.get("plugins").get(slug), **parser_config)
                for slug in self.data.get("plugins")
            ]
        else:
            self.plugins = []
        # Add Themes ; Make sure the main theme is not displayed twice
        if "themes" in self.data:
            self.themes = [
                Theme(self.data.get("themes").get(slug), **parser_config)
                for slug in self.data.get("themes")
                if not self.main_theme or slug != self.main_theme.slug
            ]
        else:
            self.themes = []
        # Add Interesting findings
        if "interesting_findings" in self.data:
            self.interesting_findings = [
                InterestingFinding(finding, **parser_config)
                for finding in self.data.get("interesting_findings")
            ]
        else:
            self.interesting_findings = []
        # Add Timthumbs
        if "timthumbs" in self.data:
            self.timthumbs = [
                Timthumb(url, self.data.get("timthumbs").get(url), **parser_config)
                for url in self.data.get("timthumbs")
            ]
        else:
            self.timthumbs = []
        # Add DBExport
        if "db_exports" in self.data:
            self.db_exports = [
                DBExport(url, self.data.get("db_exports").get(url), **parser_config)
                for url in self.data.get("db_exports")
            ]
        else:
            self.db_exports = []
        # Add Users
        if "users" in self.data:
            self.users = [
                User(url, self.data.get("users").get(url), **parser_config)
                for url in self.data.get("users")
            ]
        else:
            self.users = []
        # Add Medias
        if "medias" in self.data:
            self.medias = [
                Media(url, self.data.get("medias").get(url), **parser_config)
                for url in self.data.get("medias")
            ]
        else:
            self.medias = []
        # Add Config backups
        if "config_backups" in self.data:
            self.config_backups = [
                ConfigBackup(
                    url, self.data.get("config_backups").get(url), **parser_config
                )
                for url in self.data.get("config_backups")
            ]
        else:
            self.config_backups = []
        # Add VulnAPI
        if "vuln_api" in self.data:
            self.vuln_api = VulnAPI(self.data.get("vuln_api"), **parser_config)
        else:
            self.vuln_api = None
        # Add Password attack
        if self.data.get("password_attack", None):
            self.password_attack = PasswordAttack(
                self.data.get("password_attack"), **parser_config
            )
        else:
            self.password_attack = None
        # Add Not fully configured
        if self.data.get("not_fully_configured", None):
            self.not_fully_configured = NotFullyConfigured(
                self.data.get("not_fully_configured"), **parser_config
            )
        else:
            self.not_fully_configured = None
        # Add
        if self.data.get("banner", None):
            self.banner = Banner(self.data.get("banner"), **parser_config)
        else:
            self.banner = None
        # Add ScanStarted
        if "target_url" in self.data:
            self.scan_started = ScanStarted(self.data, **parser_config)
        else:
            self.scan_started = None
        # Add ScanFinished
        if "elapsed" in self.data:
            self.scan_finished = ScanFinished(self.data, **parser_config)
        else:
            self.scan_finished = None

        # Add Scan aborted error
        if self.data.get("scan_aborted", None):
            self.error = "Scan Aborted: {}".format(self.data["scan_aborted"])
        else:
            self.error = None

        # All all components to list
        self.components = [
            c
            for c in [self.version, self.main_theme]
            + self.plugins
            + self.themes
            + self.interesting_findings
            + [self.password_attack, self.not_fully_configured]
            + self.timthumbs
            + self.db_exports
            + self.users
            + self.medias
            + self.config_backups
            + [self.vuln_api, self.banner, self.scan_started, self.scan_finished]
            if c
        ]

    def get_infos(self):
        """Get all infos from all components and add false positives as infos with "[False positive]" prefix"""
        infos = []
        for component in self.components:
            infos.extend(component.get_infos())

            if (
                isinstance(component, _CoreFinding)
                and component.component_is_false_positive()
            ):
                # If all vulns are ignored, add component message to infos
                actually_false_positives = [
                    warning
                    for warning in component.get_warnings()
                    if not self.is_false_positive(warning)
                ]
                # Automatically add wp item infos if all vuln are ignored and component does not present another issue
                infos.extend(actually_false_positives)

            for alert in component.get_alerts() + component.get_warnings():
                if self.is_false_positive(alert):
                    infos.append("[False positive]\n" + alert)

        return infos

    def get_warnings(self):
        """Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored"""
        warnings = []
        for component in self.components:

            # Ignore false positives warnings
            if (
                isinstance(component, _CoreFinding)
                and component.component_is_false_positive()
            ):
                # Automatically remove wp item warning if all vuln are ignored and component does not present another issue
                component_warnings = []

            else:
                component_warnings = [
                    warning
                    for warning in component.get_warnings()
                    if not self.is_false_positive(warning)
                ]

            warnings.extend(component_warnings)

        return warnings

    def get_alerts(self):
        """Get all alerts from all components and igore false positives"""
        alerts = []
        for component in self.components:
            alerts.extend(
                [
                    alert
                    for alert in component.get_alerts()
                    if not self.is_false_positive(alert)
                ]
            )
        return alerts

    def get_results(self):
        results = _WPScanResults()
        results["infos"] = self.get_infos()
        results["warnings"] = self.get_warnings()
        results["alerts"] = self.get_alerts()
        results["summary"]["table"] = self.get_summary_list()
        results["summary"]["line"] = self.get_summary_line()
        results["error"] = self.get_error()
        return dict(results)

    def get_core_findings(self):
        """ Get only core findings. Core findings appears in the table summary.  """
        core = []
        for component in self.components:
            if isinstance(component, _CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self):
        """Return a list of dict with all plugins, vuls, and statuses.  """
        summary_table = []
        for component in self.get_core_findings():
            row = _WPScanResultsSummaryRow(
                {
                    "Component": component.get_name(),
                    "Version": component.get_version(),
                    "Version State": component.get_version_status(),
                    "Vulnerabilities": component.get_vulnerabilities_string(),
                    "Status": component.get_status(),
                }
            )
            summary_table.append(dict(row))
        return summary_table

    def get_error(self):
        if self.error:
            return self.error
        else:
            return None
