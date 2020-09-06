"""
WPScan Output Parser technical documentation.  



"""

VERSION='1.3'

import json, re

###################### IMPORTS  ######################

from .parser import ( _Parser, _WPScanResults, _WPScanResultsSummaryRow, _CoreFinding, InterestingFinding, 
    WordPressVersion, Plugin, MainTheme, Theme, Timthumb, DBExport, User, Media, ConfigBackup, 
    VulnAPI, PasswordAttack, NotFullyConfigured, Banner, ScanStarted, ScanFinished )
from .formatter import build_message

####################### INTERFACE METHODS ####################

def parse_results_from_string(wpscan_output_string, false_positives_strings=None, show_all_details=False):
    """ Parse any WPScan output string. 
    
    - wpscan_output_string: WPScan output as string
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
    Return the results as dict object"""
    try:
        data=json.loads(wpscan_output_string)
    except ValueError: 
        parser=WPScanCliParser(wpscan_output_string, false_positives_strings)
    else:  
        parser=WPScanJsonParser(data, false_positives_strings, show_all_details)
    return (parser.get_results())

def parse_results_from_file(wpscan_output_file, false_positives_strings=None, show_all_details=False):
    """ Prse any WPScan output file. 
    
    - wpscan_output_file: Path to WPScan output file
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
     Return the results as dict object"""
    with open(wpscan_output_file, 'r', encoding='utf-8') as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(wpscan_out_string, false_positives_strings=false_positives_strings, show_all_details=show_all_details)
    
    return results

def format_results(results, format):
    """
    Format the results dict into a "html", "cli" or "json" string.  

    - results: resutlts dict objject  
    - format: in "html", "cli" or "json"
    """
    if format == 'json':
        return json.dumps(dict(results), indent=4)
    else:
        return build_message(dict(results), format=format)

####################  CLI PARSER ######################

class WPScanCliParser(_Parser):
    """Main interface to parse WPScan CLI output.  

    - wpscan_output: WPScan output as string.  
    - false_positives_strings: List of false positive strings.  

    Once instanciated, wpscan_output is parsed and the following methods are accessible:  get_infos(), get_warnings(), get_alerts()

    """
    
    def __init__(self, wpscan_output, false_positives_strings=None):
        
        if not wpscan_output: wpscan_output=''
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=False)
        super().__init__(wpscan_output, **parser_config)
        self.infos, self.warnings, self.alerts = self.parse_cli(wpscan_output)

    def get_infos(self):
        """ Return all the parsed infos"""
        return self.infos

    def get_warnings(self):
        """ Return all the parsed warnings"""
        return self.warnings

    def get_alerts(self):
        """ Return all the parsed alerts"""
        return self.alerts

    def _parse_cli_toogle(self, line, warning_on, alert_on):
        # Color parsing
        if "33m[!]" in line: warning_on=True
        elif "31m[!]" in line: alert_on = True
        # No color parsing Warnings string are hard coded here
        elif "[!]" in line and any([m in line for m in [   
            "The version is out of date",
            "No WPVulnDB API Token given",
            "You can get a free API token"]]) :
            warning_on = True
        elif "[!]" in line :
            alert_on = True
        # Both method with color and no color apply supplementary proccessing 
        # Warning for insecure Wordpress and based on interesting findings strings
        if any(string in line for string in ['Insecure']+InterestingFinding.INTERESTING_FINDING_WARNING_STRINGS ): 
            warning_on = True
        # Trigger alert based on interesting finding alert strings
        if any(string in line for string in InterestingFinding.INTERESTING_FINDING_ALERT_STRINGS ):
            alert_on=True
        # Lower voice of Vulnerabilities found but not plugin version
        if 'The version could not be determined' in line and alert_on:
            alert_on = False  
            warning_on = True 
        return ((warning_on, alert_on))

    def _ignore_false_positives(self, infos, warnings, alerts):
        """Process false positives"""
        for alert in warnings+alerts:
            if self.is_false_positive(alert):
                try: alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append("[False positive]\n{}".format(alert))

        return infos, warnings, alerts
    
    def parse_cli(self, wpscan_output):
        """ Parse the ( messages, warnings, alerts ) from WPScan CLI output string.  
        Return results as tuple( messages, warnings, alerts ).  """
        # Init scan messages
        ( messages, warnings, alerts ) = ([],[],[])
        # Init messages toogles
        warning_on, alert_on = False, False
        message_lines=[] 
        current_message=""

        # Every blank ("") line will be considered as a message separator
        for line in wpscan_output.splitlines()+[""]:

            # Parse all output lines and build infos, warnings and alerts
            line=line.strip()
            
            # Parse line
            warning_on, alert_on = self._parse_cli_toogle(line, warning_on, alert_on)

            # Remove colorization anyway after parsing
            line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)
            # Append line to message. Handle the begin of the message case
            message_lines.append(line)

            # Build message
            current_message='\n'.join([m for m in message_lines if m not in ["","|"]]).strip()

            # Message separator just a white line.
            # Only if the message if not empty. 
            if ( line.strip() not in [""] or current_message.strip() == "" ) : 
                continue

            # End of the message

            # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
            if (alert_on or warning_on) and any(s in current_message for s in ['vulnerabilities identified','vulnerability identified']) : 
                messages_separated=[]
                msg=[]
                for l in message_lines+["|"]:
                    if l.strip() == "|":
                        messages_separated.append('\n'.join([ m for m in msg if m not in ["","|"]] ))
                        msg=[]
                    msg.append(l)

                # Append Vulnerabilities messages to ALERTS and other infos in one message
                vulnerabilities = [ m for m in messages_separated if '| [!] Title' in m.splitlines()[0] ]

                # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
                plugin_infos='\n'.join([ m for m in messages_separated if '| [!] Title' not in m.splitlines()[0] ])
                
                if ( len([v for v in vulnerabilities if not self.is_false_positive(v)])>0 and 
                    "The version could not be determined" in plugin_infos) :
                    warnings.append(plugin_infos+"\nAll known vulnerabilities are listed")
                else:
                    messages.append(plugin_infos)

                if alert_on: alerts.extend(vulnerabilities)
                elif warning_on: warnings.extend(vulnerabilities)

            elif warning_on: warnings.append(current_message)
            else: messages.append(current_message)
            message_lines=[]
            current_message=""
            # Reset Toogle Warning/Alert
            warning_on, alert_on = False, False

        return (self._ignore_false_positives( messages, warnings, alerts ))

    def get_error(self):
        if 'Scan Aborted' in self.data:
            return 'WPScan failed: {}'.format('\n'.join(line for line in self.data.splitlines() if 'Scan Aborted' in line))
        else:
            return None
        
    def get_results(self):
        """
        Returns a dictionnary structure like: 
        ```
        {
        'infos':[],
        'warnings':[],
        'alerts':[],
        'summary':{
            'table':None, 
            'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
            },
        'error':None
        }   
        ```
        """
        results = _WPScanResults()
        results['infos']=self.get_infos()
        results['warnings']=self.get_warnings()
        results['alerts']=self.get_alerts()
        results['summary']['line']=self.get_summary_line()
        results['error']=self.get_error()
        return dict(results)

#################### JSON PARSER ######################

class WPScanJsonParser(_Parser):
    """Main interface to parse WPScan JSON data
    
    - data: The JSON structure of the WPScan output.    
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).  

    Once instanciated, the following methods are accessible: get_infos(), get_warnings(), get_alerts() 
    
    And the following properties are accessible:  
            version, main_theme, plugins, themes, interesting_findings, password_attack, 
            not_fully_configured, timthumbs, db_exports, users, medias, config_backups, 
            vuln_api, banner, scan_started, scan_finished
    """
    
    def __init__(self, data, false_positives_strings=None, show_all_details=False):
        
        if not data: data={}
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=show_all_details)
        super().__init__(data, **parser_config)
        self.components=[]
        # Add WordPressVersion
        if 'version' in data:
            self.version=WordPressVersion(data.get('version'), **parser_config)
        else:
            self.version=None
        # Add MainTheme
        if 'main_theme' in data:
            self.main_theme=MainTheme(data.get('main_theme'), **parser_config)
        else:
            self.main_theme=None
        # Add Plugins
        if 'plugins' in data:
            self.plugins=[Plugin(data.get('plugins').get(slug), **parser_config) for slug in data.get('plugins')]
        else:
            self.plugins=[]
        # Add Themes ; Make sure the main theme is not displayed twice
        if 'themes' in data:
            self.themes=[Theme(data.get('themes').get(slug), **parser_config) for slug in data.get('themes') if not self.main_theme or slug!=self.main_theme.slug]
        else:
            self.themes=[]
        # Add Interesting findings
        if 'interesting_findings' in data:
            self.interesting_findings=[InterestingFinding(finding, **parser_config) for finding in data.get('interesting_findings')]
        else:
            self.interesting_findings=[]
        # Add Timthumbs
        if 'timthumbs' in data:
            self.timthumbs=[Timthumb(url, data.get('timthumbs').get(url), **parser_config) for url in data.get('timthumbs')]
        else:
            self.timthumbs=[]
        # Add DBExport
        if 'db_exports' in data:
            self.db_exports=[DBExport(url, data.get('db_exports').get(url), **parser_config) for url in data.get('db_exports')]
        else:
            self.db_exports=[]
        # Add Users
        if 'users' in data:
            self.users=[User(url, data.get('users').get(url), **parser_config) for url in data.get('users')]
        else:
            self.users=[]
        # Add Medias
        if 'medias' in data:
            self.medias=[Media(url, data.get('medias').get(url), **parser_config) for url in data.get('medias')]
        else:
            self.medias=[]
        # Add Config backups
        if 'config_backups' in data:
            self.config_backups=[ConfigBackup(url, data.get('config_backups').get(url), **parser_config) for url in data.get('config_backups')]
        else:
            self.config_backups=[]
        # Add VulnAPI 
        if 'vuln_api' in data:
            self.vuln_api=VulnAPI(data.get('vuln_api'), **parser_config)
        else:
            self.vuln_api=None
        # Add Password attack
        if data.get('password_attack', None):
            self.password_attack=PasswordAttack(data.get('password_attack'), **parser_config)
        else: 
            self.password_attack=None
        # Add Not fully configured
        if data.get('not_fully_configured', None):
            self.not_fully_configured=NotFullyConfigured(data.get('not_fully_configured'), **parser_config)
        else:
            self.not_fully_configured=None
        # Add 
        if data.get('banner', None):
            self.banner=Banner(data.get('banner'), **parser_config)
        else:
            self.banner=None
        # Add ScanStarted
        if 'target_url' in data:
            self.scan_started=ScanStarted(data, **parser_config)
        else:
            self.scan_started=None
        # Add ScanFinished
        if 'enlapsed' in data:
            self.scan_finished=ScanFinished(data, **parser_config)
        else:
            self.scan_finished=None
        # Add Scan aborted error
        if data.get('scan_aborted', None):
            self.error = 'Scan Aborted: {}'.format(data['scan_aborted'])
        else:
            self.error=None
        # All all components to list
        self.components = [ c for c in [self.version, self.main_theme] + \
                            self.plugins + self.themes + \
                            self.interesting_findings + [self.password_attack, self.not_fully_configured] + \
                            self.timthumbs + self.db_exports + \
                            self.users + self.medias + \
                            self.config_backups + [self.vuln_api, self.banner, self.scan_started, self.scan_finished] if c ]

    def get_infos(self):
        """Get all infos from all components and add false positives as infos with "[False positive]" prefix"""
        infos=[]
        for component in self.components:
            infos.extend(component.get_infos())

            # If all vulns are ignored, add component message to infos
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically add wp item infos if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and 'The version could not be determined' in component_warnings[0] 
                and not "Directory listing is enabled" in component_warnings[0] 
                and not "An error log file has been found" in component_warnings[0] ) :
                infos.extend(component_warnings)

            for alert in component.get_alerts()+component.get_warnings():
                if self.is_false_positive(alert):
                    infos.append("[False positive]\n"+alert)

        return infos

    def get_warnings(self):
        """Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored"""
        warnings=[]
        for component in self.components:
            # Ignore false positives warnings
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically remove wp item warning if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and 'The version could not be determined' in component_warnings[0] 
                and not "Directory listing is enabled" in component_warnings[0] 
                and not "An error log file has been found" in component_warnings[0] ) :
                component_warnings=[]

            warnings.extend(component_warnings)
            
        return warnings

    def get_alerts(self):
        """Get all alerts from all components and igore false positives"""
        alerts=[]
        for component in self.components:
            alerts.extend([ alert for alert in component.get_alerts() if not self.is_false_positive(alert) ])
        return alerts

    def get_results(self):
        results = _WPScanResults()
        results['infos']=self.get_infos()
        results['warnings']=self.get_warnings()
        results['alerts']=self.get_alerts()
        results['summary']['table']=self.get_summary_list()
        results['summary']['line']=self.get_summary_line()
        results['error']=self.get_error()
        return dict(results)

    def get_core_findings(self):
        """ Get only core findings. Core findings appears in the table summary.  """
        core=[]
        for component in self.components:
            if isinstance(component, _CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self):
        """Return a list of dict with all plugins, vuls, and statuses.  """
        summary_table=[]
        for component in self.get_core_findings():
            row=_WPScanResultsSummaryRow({
                'Component': component.get_name(),
                'Version': component.get_version(),
                'Version State': component.get_version_status(),
                'Vulnerabilities': component.get_vulnerabilities_string(),
                'Status': component.get_status()
            })
            summary_table.append(dict(row))
        return summary_table

    def get_error(self):
        if self.error:
            return 'WPScan failed: {}'.format(self.error)
        else:
            return None

