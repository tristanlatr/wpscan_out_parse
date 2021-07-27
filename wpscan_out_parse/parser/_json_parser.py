from typing import Any, Callable, Dict, Sequence, List, Optional, Type, Union, overload
from itertools import chain
from .base import Component, Parser
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
from .components._parts.finding import _CoreFinding
from .results import WPScanResults, WPScanResultsSummaryRow

#################### JSON PARSER ######################

_NoSlugComponent = Union[VulnAPI,
                        NotFullyConfigured,
                        Banner,
                        ScanStarted,
                        ScanFinished,
                        WordPressVersion,
                        MainTheme,
                        PasswordAttack,
                        InterestingFinding,]
                        
_OtherSlugComponent = Union[Timthumb,
                        DBExport,
                        User,
                        Media,
                        ConfigBackup,]

_PrincipalSlugComponent = Union[Plugin, Theme,]

class WPScanJsonParser(Parser):
    """Main interface to parse WPScan JSON data

    - data: The JSON structure of the WPScan output.
    - false_positives_strings: List of false positive strings.
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).

    All objects implements `get_alerts()`, `get_warnings()` and `get_infos()`
    """

    def __init__(self, data: Dict[str, Any], false_positives_strings:Optional[Sequence[str]]=None, show_all_details:bool=False) -> None:
        """Parser config: false positives string and verbosity (not available with cli parser)"""

        self._parser_config = dict(
            false_positives_strings=false_positives_strings,
            show_all_details=show_all_details,
        )
        super().__init__(data, **self._parser_config)

        # All all components to list
        self.components : List[Component] = []

        # Add WordPressVersion
        self.version: Optional[WordPressVersion] = self._init_component("version", WordPressVersion)
        
        # Add MainTheme
        self.main_theme: Optional[MainTheme] = self._init_component("main_theme", MainTheme)
        
        # Add Plugins
        self.plugins: Sequence[Plugin] = self._init_component_dict("plugins", Plugin)
        
        # Add Themes ; 
        self.themes: Sequence[Theme] = self._init_component_dict("themes", Theme, 
                                        comp_filter=lambda slug: not self.main_theme or slug != self.main_theme.slug)
        
        # Add Interesting findings
        self.interesting_findings: Sequence[InterestingFinding] = self._init_component_list("interesting_findings", InterestingFinding)
        
        # Add Timthumbs
        self.timthumbs: Sequence[Timthumb] = self._init_component_dict("timthumbs", Timthumb)
        
        # Add DBExport
        self.db_exports: Sequence[DBExport] = self._init_component_dict("db_exports", DBExport)
        
        # Add Users
        self.users: Sequence[User] = self._init_component_dict("users", User)
        
        # Add Medias
        self.medias: Sequence[Media] = self._init_component_dict("medias", Media)
        
        # Add Config backups
        self.config_backups: Sequence[ConfigBackup] = self._init_component_dict("config_backups", ConfigBackup)
        
        # Add VulnAPI
        self.vuln_api: Optional[VulnAPI] = self._init_component("vuln_api", VulnAPI)
        
        # Add Password attack
        self.password_attack: Optional[PasswordAttack] = self._init_component("password_attack", PasswordAttack)
        
        # Add Not fully configured
        self.not_fully_configured: Optional[NotFullyConfigured] = self._init_component("not_fully_configured", NotFullyConfigured, True)
        
        # Add Banner
        self.banner: Optional[Banner] = self._init_component("banner", Banner)
        
        # Add ScanStarted
        self.scan_started: Optional[ScanStarted] = self._init_component("target_url", ScanStarted, True)
        
        # Add ScanFinished
        self.scan_finished: Optional[ScanFinished] = self._init_component("elapsed", ScanFinished, True)

        # Add Scan aborted error
        self._error: Optional[str]
        if self.data.get("scan_aborted", None):
            self._error = "Scan Aborted: {}".format(self.data["scan_aborted"])
        else:
            self._error = None

    @overload
    def _init_component_dict(self, name: str, comp_type: Type[Plugin], 
                             comp_filter: Callable[[str], bool] = lambda slug:True) -> Sequence[Plugin]: ...
    @overload
    def _init_component_dict(self, name: str, comp_type: Type[Theme], 
                             comp_filter: Callable[[str], bool] = lambda slug:True) -> Sequence[Theme]: ...
    @overload
    def _init_component_dict(self, name: str, comp_type: Type[_OtherSlugComponent], 
                             comp_filter: Callable[[str], bool] = lambda slug:True) -> Sequence[Any]: ...
    def _init_component_dict(self, name: str, comp_type: Union[Type[_PrincipalSlugComponent], Type[_OtherSlugComponent]], 
                             comp_filter: Callable[[str], bool] = lambda slug:True) -> Sequence[Union[_PrincipalSlugComponent, _OtherSlugComponent]]:
        comps: Sequence[Union[_PrincipalSlugComponent, _OtherSlugComponent]]
        if name in self.data:
            d = self.data.get(name)
            assert isinstance(d, dict), str(d)
            comps = [
                comp_type(
                    url, d[url], **self._parser_config
                ) if not issubclass(comp_type, (Plugin, Theme)) else comp_type(
                    d[url], **self._parser_config
                )
                for url in d if comp_filter(url)
            ]
            self.components.extend(comps)
        else:
            comps = []
        return comps

    def _init_component_list(self, name: str, comp_type: Type[_NoSlugComponent]) -> Sequence[Any]:
        comps: Sequence[_NoSlugComponent]
        if name in self.data:
            d = self.data.get(name)
            assert isinstance(d, list), str(d)
            comps = [
                comp_type(finding, **self._parser_config)
                for finding in d
            ]
            self.components.extend(comps)
        else:
            comps = []
        return comps

    def _init_component(self, name: str, comp_type: Type[_NoSlugComponent], pass_all_data:bool = False) -> Optional[Any]:
        """
        If pass_all_data is True: name is only used to check if the new component should be created. 
            Then it passes all self.data dict to the child constructor. 
        """
        comp: Optional[_NoSlugComponent]
        if name in self.data:
            comp = comp_type(self.data if pass_all_data else self.data[name], **self._parser_config)
            self.components.append(comp)
        else:
            comp = None
        return comp

    def get_infos(self) -> Sequence[str]:
        """Get all infos from all components and add false positives as infos with "[False positive]" prefix"""
        infos:List[str] = []
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

            for alert in chain(component.get_alerts(), component.get_warnings()):
                if self.is_false_positive(alert):
                    infos.append("[False positive]\n" + alert)

        return infos

    def get_warnings(self) -> Sequence[str]:
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

    def get_alerts(self) -> Sequence[str]:
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

    def get_results(self) -> WPScanResults:
        results = WPScanResults()
        results["infos"] = self.get_infos()
        results["warnings"] = self.get_warnings()
        results["alerts"] = self.get_alerts()
        results["summary"]["table"] = self.get_summary_list() # type: ignore
        results["summary"]["line"] = self.get_summary_line() # type: ignore
        results["error"] = self.get_error()
        return results

    def get_core_findings(self) -> Sequence[_CoreFinding]:
        """ Get only core findings. Core findings appears in the table summary.  """
        core = []
        for component in self.components:
            if isinstance(component, _CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self) -> List[WPScanResultsSummaryRow]:
        """Return a list of dict with all plugins, vuls, and statuses.  """
        summary_table = []
        for component in self.get_core_findings():
            row = WPScanResultsSummaryRow(
                **{
                    "Component": component.get_name(),
                    "Version": component.get_version(),
                    "Version State": component.get_version_status(),
                    "Vulnerabilities": component.get_vulnerabilities_string(),
                    "Status": component.get_status(),
                }
            )
            summary_table.append(row)
        return summary_table

    def get_error(self) -> Optional[str]:
        if self._error:
            return self._error
        else:
            return None
