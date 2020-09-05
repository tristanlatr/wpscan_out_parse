#! /usr/bin/env python3
# 
# WPScan output parser
# 
# Authors: Florian Roth, Tristan Landès
# Summary design from Lukas Pustina (lukaspustina)
#
# DISCLAIMER - USE AT YOUR OWN RISK.

# Parse know vulnerabilities
# Parse vulnerability data and make more human readable.
# NOTE: You need an API token for the WPVulnDB vulnerability data.

"""
All the WPScan fields for the JSON output in the views/json folders at:

https://github.com/wpscanteam/CMSScanner/tree/master/app/views/json
https://github.com/wpscanteam/wpscan/tree/master/app/views/json

Here are some other inspirational ressources found about parsing wpscan json

Generates a nice table output (Rust code) 
    https://github.com/lukaspustina/wpscan-analyze
    Parser code: 
        https://github.com/lukaspustina/wpscan-analyze/blob/master/src/analyze.rs
Python parser (do not parse for vulnerable theme or outdated warnings) 
    https://github.com/aaronweaver/AppSecPipeline/blob/master/tools/wpscan/parser.py
Vulcan wpscan (Go) 
    https://github.com/adevinta/vulcan-checks/blob/master/cmd/vulcan-wpscan/wpscan.go
    Great job listing all the fields, is the list complete ?
Dradis ruby json Parser 
    https://github.com/dradis/dradis-wpscan/blob/master/lib/dradis/plugins/wpscan/importer.rb : 
    No warnings neither but probably the clearest code

Ressource Parsing CLI output:
    List of all icons: https://github.com/wpscanteam/CMSScanner/blob/master/app/formatters/cli.rb
"""

import collections
import json
import re
from abc import ABC, abstractmethod

####################### INTERFACE METHODS ####################

def parse_results_from_string(wpscan_output_string, false_positives_strings=None, show_all=False):
    """ Helper function to parse any WPScan output. Return the full dict object"""
    is_json=False
    try:
        data=json.loads(wpscan_output_string)
        is_json=True
    except ValueError: pass

    if is_json: 
        parser=WPScanJsonParser(data, false_positives_strings, show_all)
    else:  
        parser=WPScanCliParser(wpscan_output_string, false_positives_strings)

    return (parser.get_results())

def parse_results_from_file(wpscan_output_file, false_positives_strings=None, show_all=False):
    with open(wpscan_output_file, 'r') as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(wpscan_out_string, false_positives_strings=false_positives_strings, show_all=show_all)
    
    return results


############ RESULTS CLASS ###########################

TEMPLATE_SCAN_RESULTS={
'infos':None,
'warnings':None,
'alerts':None,
'summary':{'table':None, 'line':None},
'error':None}   

TEMPLATE_SCAN_RESULTS_SUMMARY_ROW={
    'Component': None,
    'Version': None,
    'Version State': None,
    'Vulnerabilities': None,
    'Status': None
}

class WPScanResults(collections.UserDict):

    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS.keys():
            if key not in self.data:
                self.data[key]=TEMPLATE_SCAN_RESULTS[key]

class WPScanResultsSummaryRow(collections.UserDict):
    
    def __init__(self, data=None):
        super().__init__(data)
        # Init dict with default values if not already passed with data
        for key in TEMPLATE_SCAN_RESULTS_SUMMARY_ROW.keys():
            if key not in self.data:
                self.data[key]=TEMPLATE_SCAN_RESULTS_SUMMARY_ROW[key]

########### BASE CLASS FOR CLI AND JSON PARSERS ##########

class Component(ABC):
    
    def __init__(self, data, false_positives_strings, show_all_details): 
        """Base abstract class for all WPScan JSON and CLI components"""
        if not data: data={}
        self.data=data
        self.false_positives_strings=false_positives_strings if false_positives_strings else []
        self.show_all_details=False
        if show_all_details:
            self.show_all_details=True

    def is_false_positive(self, string):
        """False Positive Detection"""
        if not self.false_positives_strings:
            return False
        for fp_string in self.false_positives_strings:
            if fp_string in string:
                return True
        return False

    @abstractmethod
    def get_infos(self):
        pass

    @abstractmethod
    def get_warnings(self):
        pass

    @abstractmethod
    def get_alerts(self):
        pass

class Parser(Component):
    def __init__(self, data, *args, **kwargs): 
        if not data: data={}
        super().__init__(data, *args, **kwargs)
    
    @abstractmethod
    def get_results(self):
        pass

    def get_summary_line(self):
        """Return the summary string in one line"""
        line='WPScan result summary: alerts={}, warnings={}, infos={}, error={}'.format(
                len(self.get_alerts()),
                len(self.get_warnings()), 
                len(self.get_infos()), 
                '1' if self.get_error() else '0' )
        return line
    
    @abstractmethod
    def get_error(self):
        pass

########################  CLI PARSER ######################

class WPScanCliParser(Parser):
    
    def __init__(self, wpscan_output, false_positives_strings=None):
        """Main interface to parse WPScan JSON data"""
        if not wpscan_output: wpscan_output=''
        # Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=False)
        super().__init__(wpscan_output, **parser_config)
        self.infos, self.warnings, self.alerts = self.parse_cli(wpscan_output)

    def get_infos(self):
        return self.infos

    def get_warnings(self):
        return self.warnings

    def get_alerts(self):
        return self.alerts

    def parse_cli_toogle(self, line, warning_on, alert_on):
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

    def ignore_false_positives(self, infos, warnings, alerts):
        """Process false positives"""
        for alert in warnings+alerts:
            if self.is_false_positive(alert):
                try: alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append("[False positive]\n{}".format(alert))

        return infos, warnings, alerts
    
    def parse_cli(self, wpscan_output):
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
            warning_on, alert_on = self.parse_cli_toogle(line, warning_on, alert_on)

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

        return (self.ignore_false_positives( messages, warnings, alerts ))

    def get_error(self):
        if 'Scan Aborted' in self.data:
            return 'WPScan failed: {}'.format('\n'.join(line for line in self.data.splitlines() if 'Scan Aborted' in line))
        else:
            return None
        
    def get_results(self):
        results = WPScanResults()
        results['infos']=self.get_infos()
        results['warnings']=self.get_warnings()
        results['alerts']=self.get_alerts()
        results['summary']['line']=self.get_summary_line()
        results['error']=self.get_error()
        return dict(results)

#################### JSON PARSER ######################

class WPScanJsonParser(Parser):
    
    def __init__(self, data, false_positives_strings=None, show_all_details=False):
        """Main interface to parse WPScan JSON data"""
        if not data: data={}
        # Parser config: false positives string and verbosity (not available with cli parser)
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
        # Add ScanFinished''
        if 'enlapsed' in data:
            self.scan_finished=ScanFinished(data, **parser_config)
        else:
            self.scan_finished=None
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
        """Add false positives as infos with "[False positive]" prefix"""
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
        """Igore false positives and automatically remove special warning if all vuln are ignored"""
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
        """Igore false positives"""
        alerts=[]
        for component in self.components:
            alerts.extend([ alert for alert in component.get_alerts() if not self.is_false_positive(alert) ])
        return alerts

    def get_results(self):
        results = WPScanResults()
        results['infos']=self.get_infos()
        results['warnings']=self.get_warnings()
        results['alerts']=self.get_alerts()
        results['summary']['table']=self.get_summary_list()
        results['summary']['line']=self.get_summary_line()
        results['error']=self.get_error()
        return dict(results)

    def get_core_components(self):
        core=[]
        for component in self.components:
            if isinstance(component, CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self):
        """Return a nice list of dict with all plugins, vuls, and statuses. Only plugin or component with issues by default"""
        summary_table=[]
        for component in self.get_core_components():
            row=WPScanResultsSummaryRow({
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

############ WPSCAN JSON COMPONENTS DATA STRUCTURE ##########

class CoreFinding(ABC):

    @abstractmethod
    def get_version(self):
        pass
    @abstractmethod
    def get_version_status(self):
        pass
    @abstractmethod
    def get_vulnerabilities_string(self):
        pass

    @abstractmethod
    def get_name(self):
        pass
    @abstractmethod
    def should_display_in_summary(self):
        pass

    def get_status(self):
        try:
            return 'Alert' if self.get_alerts() else 'Warning' if self.get_warnings() else 'Ok'
        except AttributeError:
            return None

class CoreFindingNoVersion(CoreFinding):
    def get_version(self):
        return "N/A"
    def get_version_status(self):
        return "N/A"
    def get_vulnerabilities_string(self):
        return ''

class Finding(Component):
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.found_by=data.get("found_by", None)
        self.confidence=data.get("confidence", None)
        self.interesting_entries=data.get("interesting_entries", None)
        self.confirmed_by=data.get("confirmed_by", None)
        self.vulnerabilities=[Vulnerability(vuln, *args, **kwargs) for vuln in data.get("vulnerabilities", [])]
        self.vulnerabilities=[Vulnerability(vuln, *args, **kwargs) for vuln in data.get("vulnerabilities", [])]
        self.references=data.get("references", None)

    def get_alerts(self):
        """Return list of vulnerabilities"""
        alerts=[]
        for v in self.vulnerabilities:
            alerts.extend(v.get_alerts())
        return alerts

    def get_infos(self):
        """Return 1 info, only interesting entries. If no interesting entries: return an empty info string (to avoid errors)"""
        info=""
        if self.interesting_entries: 
            info+="Interesting entries: \n- {}".format('\n- '.join(self.interesting_entries))
            if self.show_all_details:
                info+='\n'
        if self.show_all_details:
            if self.found_by: 
                info+="Found by: {} ".format(self.found_by)
            if self.confidence: 
                info+="(confidence: {})".format(self.confidence)
            # info+="\n"
            if self.confirmed_by: 
                info+="\nConfirmed by: "
                for entry in self.confirmed_by:
                    info+="\n- {} ".format(entry)
                    if self.confirmed_by[entry].get('confidence', None): 
                        info+="(confidence: {})".format(self.confirmed_by[entry]['confidence'])
                    if self.confirmed_by.get("interesting_entries", None):
                        info+="\n  Interesting entries: \n  - {}".format('\n  - '.join(self.confirmed_by.get("interesting_entries")))

        return [info]

    def get_references_str(self):
        """Process CVE, WPVulnDB, ExploitDB and Metasploit references to add links"""
        alert=""
        if self.references: 
            alert+='References: '
            for ref in self.references:
                if ref == 'cve':
                    for cve in self.references[ref]: 
                        alert+="\n- CVE: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{}".format(cve)
                elif ref == 'wpvulndb': 
                    for wpvulndb in self.references[ref]:
                        alert+="\n- WPVulnDB: https://wpvulndb.com/vulnerabilities/{}".format(wpvulndb)
                elif ref == 'metasploit': 
                    for metasploit in self.references[ref]:
                        alert+="\n- Metasploit: https://www.rapid7.com/db/modules/{}".format(metasploit)
                elif ref == 'exploitdb': 
                    for exploitdb in self.references[ref]:
                        alert+="\n- ExploitDB: https://www.exploit-db.com/exploits/{}".format(exploitdb)
                elif ref == 'packetstorm': 
                    for packetstorm in self.references[ref]:
                        alert+="\n- Packetstorm: https://packetstormsecurity.com/files/{}".format(packetstorm)
                
                else:
                    for link in self.references[ref]:
                        alert+="\n- {}: {}".format(ref.title(), link)
        return alert

class Vulnerability(Finding):
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.title=data.get('title', None)
        self.cvss=data.get('cvss', None)
        self.fixed_in=data.get('fixed_in', None)

    def get_alerts(self):
        """Return 1 alert. First line of alert string contain the vulnerability title. Process CVE, WPVulnDB, ExploitDB and Metasploit references to add links"""
        alert="Vulnerability: {}".format(self.title)

        if self.cvss: 
            alert+='\nCVSS: {}'.format(self.cvss)
        if self.fixed_in: 
            alert+='\nFixed in: {}'.format(self.fixed_in)
        else:
            alert+='\nNo known fix'
        if self.references: 
            alert+='\n{}'.format(self.get_references_str())
        return([alert])

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

class InterestingFinding(Finding):

    INTERESTING_FINDING_WARNING_STRINGS=[ 
        "Upload directory has listing enabled",
        "Registration is enabled",
        "Debug Log found",                              "codex.wordpress.org/Debugging_in_WordPress",
        "Fantastico list found",                        "www.acunetix.com/vulnerabilities/fantastico-fileslist/" ]

    INTERESTING_FINDING_ALERT_STRINGS=[
        "SQL Dump found", 
        "Full Path Disclosure found",                   "www.owasp.org/index.php/Full_Path_Disclosure",
                                                        "codex.wordpress.org/Resetting_Your_Password#Using_the_Emergency_Password_Reset_Script",
                                                        "www.exploit-db.com/ghdb/3981/",
        "A backup directory has been found",            "github.com/wpscanteam/wpscan/issues/422",
        "ThemeMakers migration file found",             "packetstormsecurity.com/files/131957",
        "Search Replace DB script found",               "interconnectit.com/products/search-and-replace-for-wordpress-databases/" ]
    
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb  
        Warnings and Alerts strings are from https://github.com/wpscanteam/wpscan/blob/master/app/models/interesting_finding.rb
        """
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.url=data.get('url', None)
        self.to_s=data.get('to_s', None)
        self.type=data.get('type', None)

    def _get_infos(self):
        """Return 1 info. First line of info string is the to_s string or the finding type. Complete references links too."""
        info=""
        if self.to_s != self.url:
            info+=self.to_s
        elif self.type:
            info+=self.type.title()
        if self.url and self.url not in self.to_s:
            info+="\nURL: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0]:
            info+="\n{}".format(super().get_infos()[0])
        if self.references: 
            info+='\n{}'.format(self.get_references_str())
        return [info]

    def get_infos(self):
        """Return 1 info or 0 if finding is a warning or an alert"""
        return [ info for info in self._get_infos() if not any([string in info for string in self.INTERESTING_FINDING_WARNING_STRINGS+self.INTERESTING_FINDING_ALERT_STRINGS]) ]

    def get_warnings(self):
        """Return list of warnings if finding match warning string"""
        return [ info for info in self._get_infos() if any([string in info for string in self.INTERESTING_FINDING_WARNING_STRINGS]) ]

    def get_alerts(self):
        """Return list of alerts if finding match ALERT string"""
        return [ info for info in self._get_infos() if any([string in info for string in self.INTERESTING_FINDING_ALERT_STRINGS]) ]

class WordPressVersion(Finding, CoreFinding):
    
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.number=data.get('number', None)
        self.release_date=data.get('release_date', None)
        self.status=data.get('status', None)

    def _get_infos(self):
        """Return 1 info"""
        if self.number:
            info="Wordpress version: {}".format(self.number)
            if self.status=="latest":
                info+=" (up to date)"
            if self.release_date:
                info+="\nRelease Date: {}".format(self.release_date)
            # Not showing "Status: "
            # if self.status:
            #     info+="\nStatus: {}".format(self.status.title())  
        else:
            info="The WordPress version could not be detected"
        # If finding infos are present and show_all_details, add them
        if super().get_infos()[0] and self.show_all_details:
            info+="\n{}".format(super().get_infos()[0])
        return [info]

    def get_infos(self):
        """Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use get_warnings()"""
        if not self.get_warnings():
            return self._get_infos() 
        else:
            return []

    def get_warnings(self):
        """Return 0 or 1 warning"""
       
        if self.status=="insecure":
            warning="Outdated "
            warning+=self._get_infos()[0]
            return [warning]
        else:
            return []

    def get_alerts(self):
        """Return Wordpress Version vulnerabilities"""
        return [ "Wordpress {}".format(alert) for alert in super().get_alerts() ]
    
    def get_version(self):
        """Return the version string or 'Unknown'"""
        return self.number if self.number else 'Unknown'

    def get_version_status(self):
        if self.number:
            if self.status=="insecure":
                return "Outdated"
            elif self.status=="latest":
                return "Latest"
            else:
                return 'Unknown'
        else:
            return 'N/A'

    def get_vulnerabilities_string(self):
        return '{}'.format(len(self.vulnerabilities) if self.get_version()!='Unknown' else 'N/A')

    def get_name(self):
        return 'WordPress {} {}'.format(self.get_version(), '({})'.format(self.release_date) if self.release_date and self.number else '' )

    def should_display_in_summary(self):
        return True

class WPItemVersion(Finding):
    
    def __init__(self, data, *args, **kwargs): 
        """ Themes, plugins and timthumbs Version. From:
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb
        https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb
        """
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.number=data.get('number', None)
    
    def get_alerts(self):
        """Return any item version vulnerabilities"""
        return super().get_alerts()

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return 0 or 1 info. No infos if version could not be recognized"""
        if self.number:
            info="Version: {}".format(self.number)
            # If finding infos are present, add them
            if super().get_infos()[0] and self.show_all_details:
                info+="\n{}".format(super().get_infos()[0])
            return [info]
        else:
            return []

    def get_version(self):
        if self.get_infos():
            return self.number
        else:
            return "Unknown"

class WPItem(Finding, CoreFinding):
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.slug=data.get('slug', None)
        self.location=data.get('location', None)
        self.latest_version=data.get('latest_version', None)
        self.last_updated=data.get('last_updated', None)
        self.outdated=data.get('outdated', None)
        self.readme_url=data.get('readme_url', None)
        self.directory_listing=data.get('directory_listing', None)
        self.error_log_url=data.get('error_log_url', None) 
        self.version=WPItemVersion(data.get('version', None), *args, **kwargs)

    def _get_warnings(self):
        """Return 0 or 1 warning. The warning can contain infos about oudated plugin, directory listing or accessible error log.
        First line of warning string is the plugin slug. Location also added as a reference."""
        # Test if there is issues
        issue_data=""
        if self.outdated: 
            issue_data+="\nThe version is out of date"
        if self.directory_listing: 
            issue_data+="\nDirectory listing is enabled"
            issue_data += "\nLocation: {}".format(self.location)
        if self.error_log_url: 
            issue_data+="\nAn error log file has been found: {}".format(self.error_log_url)

        if not issue_data: 
            return [] # Return if no issues
        else: 
            return [issue_data]

    def get_alerts(self):
        """Return list of know plugin or theme vulnerability. Empty list is returned if plugin version is unrecognized"""
        alerts=[]
        if self.version.get_infos():
            alerts.extend(["{}".format(alert) for alert in super().get_alerts()])
            alerts.extend(["{}".format(alert) for alert in self.version.get_alerts()])
        return alerts

    def get_warnings(self):
        """Return plugin or theme warnings, if oudated plugin, directory listing, accessible error log and 
        for all know vulnerabilities if plugin version could not be recognized.
        Adds a special text saying the version is unrecognized if that's the case"""
        warnings=[]
        # Prepare warning string
        warning=self.slug if self.slug else str()
        # Get oudated theme warning
        if self._get_warnings():
            warning+=self._get_warnings()[0]
        if warning: warning += "\n"
        # Get generic infos
        warning+=self._get_infos()[0]
        # If vulns are found and the version is unrecognized
        if not self.version.get_infos() and super().get_alerts():
            # Adds a special text saying all vulns are listed
            warning+="\nAll known vulnerabilities are listed"
        # If vulns are found and the version is unrecognized or other issue like outdated version or directory listing enable
        if (not self.version.get_infos() and super().get_alerts()) or self._get_warnings():
            warnings.append(warning)
        # If vulns are found and the version is unrecognized : add Potential vulns
        if not self.version.get_infos() and super().get_alerts():
            warnings.extend(["Potential {}".format(warn) for warn in super().get_alerts()])
            warnings.extend(["Potential {}".format(warn) for warn in self.version.get_alerts()])
        return warnings

    def _get_infos(self):
        """Return 1 info"""
        info=""
        if self.show_all_details:
            if self.location : 
                info += "Location: {}".format(self.location)
            if self.last_updated:
                info += "\nLast Updated: {}".format(self.last_updated)
        if self.readme_url:
            if info: info+='\n'
            info += "Readme: {}".format(self.readme_url)
        # If finding infos are present, add them
        if info: info+='\n'
        if super().get_infos()[0] and self.show_all_details:
            info+="{}\n".format(super().get_infos()[0])
        if self.version.get_infos():
            info += self.version.get_infos()[0]
            if self.version.number == self.latest_version:
                info += " (up to date)"
            elif self.latest_version:
                info += " (latest is {})".format(self.latest_version)
        else:
            info += "The version could not be determined"
            if self.latest_version:
                info += " (latest is {})".format(self.latest_version)
        
        return [info]
    
    def get_infos(self):
        """Return 0 or 1 info, no info if WPItem triggered warning, use get_warnings()"""
        if not self.get_warnings():
            return [ "{}\n{}".format(self.slug, self._get_infos()[0]) ]
        else:
            return []

    def get_version(self):
        return self.version.get_version()

    def get_version_status(self):
        if self.version.get_infos():
            if self.outdated:
                return "Outdated"
            elif self.version.number == self.latest_version:
                return "Latest"
            else:
                return 'Unknown'
        else:
            return 'N/A'

    def get_vulnerabilities_string(self):
        return '{}{}'.format(len(self.vulnerabilities),' (potential)' if not self.version.get_infos() and super().get_alerts() else '')

    def should_display_in_summary(self):
        return True

class Plugin(WPItem):
    def __init__(self, data, *args, **kwargs):
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 or 0 info if pluging trigerred warning"""
        return [ "Plugin: {}".format(info) for info in super().get_infos() ]

    def get_warnings(self):
        """Return plugin warnings"""
        # Adds plugin prefix on all warnings except vulns
        return [ "{}{}".format('Plugin: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super().get_warnings() ]
    
    def get_name(self):
        return 'Plugin: {}'.format(self.slug)

class Theme(WPItem):
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.style_url=data.get('style_url', None)
        self.style_name=data.get('style_name', None)
        self.style_uri=data.get('style_uri', None)
        self.description=data.get('description', None)
        self.author=data.get('author', None)
        self.author_uri=data.get('author_uri', None)
        self.template=data.get('template', None)
        self.license=data.get('license', None)
        self.license_uri=data.get('license_uri', None)
        self.tags=data.get('tags', None)
        self.text_domain=data.get('text_domain', None)
        self.parents=[Theme(theme, *args, **kwargs) for theme in data.get('parents', [])]

    def _get_infos(self):
        """Return 1 info"""
        info=super()._get_infos()[0]

        if self.style_url:
            info+="\nStyle CSS: {}".format(self.style_url)
        if self.style_name and self.show_all_details:
            info+="\nStyle Name: {}".format(self.style_name)
        if self.style_uri:
            info+="\nStyle URI: {}".format(self.style_uri)
        if self.description and self.show_all_details:
            info+="\nDescription: {}".format(self.description)
        if self.author:
            info+="\nAuthor: {}".format(self.author)
            if self.author_uri:
                info+=" - {}".format(self.author_uri)
        if self.show_all_details:
            if self.template: 
                info+="\nTemplate: {}".format(self.template)
            if self.license:
                info+="\nLicense: {}".format(self.license)
            if self.license_uri:
                info+="\nLicense URI: {}".format(self.license_uri)
            if self.tags:
                info+="\nTags: {}".format(self.tags)
            if self.text_domain:
                info+="\nDomain: {}".format(self.text_domain)
            if self.parents:
                info+="\nParent Theme(s): {}".format(', '.join([p.slug for p in self.parents]))
        
        return [info]

    def get_infos(self):
        if super().get_infos():
            return ["Theme: {}".format(super().get_infos()[0])]
        else:
            return []

    def get_warnings(self):
        """Return theme warnings"""
        return [ "{}{}".format('Theme: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super().get_warnings() ]

    def get_name(self):
        return 'Theme: {}'.format(self.slug)

class MainTheme(Theme): 
    
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

    def get_infos(self):
        """Return 1 info"""
        return [ "Main Theme: {}".format(info) for info in super(Theme, self).get_infos() ]

    def get_warnings(self):
        """Return Main Theme warnings"""
        return [ "{}{}".format('Main Theme: ' if 'Vulnerability' not in warning.splitlines()[0] else '', warning) 
            for warning in super(Theme, self).get_warnings() ]
    
    def get_name(self):
        return 'Main Theme: {}'.format(self.slug)

class Timthumb(Finding, CoreFinding):
    
    def __init__(self, url, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.url=url
        self.version=WPItemVersion(data.get('version', None), *args, **kwargs)

    def get_infos(self):
        """Return 1 info"""
        info="Timthumb: {}".format(self.url)
        # If finding infos are present and show_all_details, add them
        if super().get_infos()[0] and self.show_all_details:
            info+="\n{}".format(super().get_infos()[0])
        if self.version.get_infos():
            info += "\n{}".format(self.version.get_infos()[0])
        else:
            info += "\nThe version could not be determined"
        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return timthumb vulnerabilities"""
        return [ "Timthumb {}".format(alert) for alert in super().get_alerts()+ self.version.get_alerts() ]

    def get_version(self):
        return self.version.get_version()

    def get_version_status(self):
        if self.version.get_infos():
            return '?'
        else:
            return 'N/A'

    def get_vulnerabilities_string(self):
        return '{}{}'.format(len(self.vulnerabilities),' (potential)' if not self.version.get_infos() and super().get_alerts() else '')

    def get_name(self):
        return 'Timthumb'

    def should_display_in_summary(self):
        return True

class DBExport(Finding, CoreFindingNoVersion):
    
    def __init__(self, url, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.url=url

    def get_alerts(self):
        """Return 1 DBExport alert"""
        alert="Database Export: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert+="\n{}".format(super().get_infos()[0])
        return [alert]
    
    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return 'Database Export'

    def should_display_in_summary(self):
        return True

class User(Finding):
    
    def __init__(self, username, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb
        And https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb
        """
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        
        self.username=username
        self.id=data.get('id', None)
        self.password=data.get('password', None)

    def get_infos(self):
        """Return 1 info"""
        info="User Identified: {}".format(self.username)
        if self.id:
            info+="\nID: {}".format(self.id)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            info+="\n{}".format(super().get_infos()[0])
        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return 0 or 1 alert. Alert if password found. Used by PasswordAttack component"""
        if self.password:
            alert="Username: {}".format(self.username)
            alert+="Password: {}".format(self.password)
            return [alert]
        else:
            return []

class PasswordAttack(Component, CoreFindingNoVersion):
    
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.users = [ User(user, data.get(user), *args, **kwargs) for user in data ] 

    def get_alerts(self):
        """Return Password Attack Valid Combinations Found alerts"""
        alerts=[]
        for user in self.users:
            alert="Password Attack Valid Combinations Found:"
            if user.get_alerts():
                alert+="\n{}".format(user.get_alerts()[0])
                alerts.append(alert)

        return alerts

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return 'Password Attack: {} found'.format(len(self.get_alerts()))

    def should_display_in_summary(self):
        return True if self.get_alerts() else False if not self.show_all_details else True

class NotFullyConfigured(Component, CoreFindingNoVersion):

    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.not_fully_configured=data
    
    def get_alerts(self):
        """Return 1 alert"""
        return ["Wordpress: {}".format(self.not_fully_configured)]
        
    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return 'Noy fully configured'

    def should_display_in_summary(self):
        return True

class Media(Finding):

    def __init__(self, url, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.url=url
    
    def get_infos(self):
        """Return 1 Media info"""
        alert="Media: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert+="\n{}".format(super().get_infos()[0])
        return [alert]
    
    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []

class ConfigBackup(Finding, CoreFindingNoVersion):

    def __init__(self, url, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        self.url=url

    def get_alerts(self):
        """Return 1 Config Backup alert"""
        alert="Config Backup: {}".format(self.url)
        # If finding infos are present, add them
        if super().get_infos()[0] and self.show_all_details:
            alert+="\n{}".format(super().get_infos()[0])
        return [alert]
    
    def get_warnings(self):
        """Return empty list"""
        return []

    def get_infos(self):
        """Return empty list"""
        return []

    def get_name(self):
        return 'Config backup'

    def should_display_in_summary(self):
        return True

class VulnAPI(Component):
    
    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)
        
        self.http_error=data.get('http_error', None)
        self.error=data.get('error', None)

        self.plan=data.get('plan', None)
        self.requests_done_during_scan=data.get('requests_done_during_scan', None)
        self.requests_remaining=data.get('requests_remaining', None)

    def get_infos(self):
        """Return 1 WPVulnDB info"""
        info="WPVulnDB API"
        info+="\nPlan: {}".format(self.plan)
        info+="\nRequests: {} done during scan, {} remaining".format(self.requests_done_during_scan, self.requests_remaining)
        return [info]
    
    def get_warnings(self):
        """Return 0 or 1 warning. VulnAPI error No WPVulnDB API Token given or HTTP errors"""
        warning=""
        if self.http_error:
            warning+="HTTP Error: {}".format(self.http_error)
        if self.error:
            warning+=self.error
        if warning:
            return [warning]
        else:
            return []

    def get_alerts(self):
        """Return empty list"""
        return []

class Banner(Component):

    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.description=data.get('description', None)
        self.version=data.get('version', None)
        self.authors=data.get('authors', None)
        self.sponsor=data.get('sponsor', None) or data.get('sponsored_by', None)

    def get_infos(self):
        info="Scanned with {}".format(self.description)
        info+='\nVersion: {}'.format(self.version)
        if self.show_all_details:
            info+='\nAuthors: {}'.format(', '.join(self.authors))
            if self.sponsor:
                info+='\nSponsor: {}'.format(self.sponsor)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []

class ScanStarted(Component):

    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.start_time=data.get('start_time', None)
        self.start_memory=data.get('start_memory', None)
        self.target_url=data.get('target_url', None)
        self.target_ip=data.get('target_ip', None)
        self.effective_url=data.get('effective_url', None)

    def get_infos(self):
        """Return 1 Scan Scanned info"""
        
        info='Target URL: {}'.format(self.target_url)
        info+='\nTarget IP: {}'.format(self.target_ip)
        info+='\nEffective URL: {}'.format(self.effective_url)
        if self.show_all_details:
            info+='\nStart Time: {}'.format(self.start_time)
            info+='\nStart Memory: {}'.format(self.start_memory)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []

class ScanFinished(Component):

    def __init__(self, data, *args, **kwargs): 
        """From https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb"""
        if not data: data={}
        super().__init__(data, *args, **kwargs)

        self.stop_time=data.get('stop_time', None)
        self.elapsed=data.get('elapsed', None)
        self.requests_done=data.get('requests_done', None)
        self.cached_requests=data.get('cached_requests', None)
        self.data_sent_humanised=data.get('data_sent_humanised', None)
        self.data_received_humanised=data.get('data_received_humanised', None)
        self.used_memory_humanised=data.get('used_memory_humanised', None)

    def get_infos(self):
        """Return 1 Scan Finished info"""
        
        info='Scan duration: {} seconds'.format(self.elapsed)
        if self.show_all_details:
            info+='\nStop Time: {}'.format(self.stop_time)
            info+='\nRequests Done: {}'.format(self.requests_done)
            info+='\nCached Requests: {}'.format(self.cached_requests)
            info+='\nData Sent: {}'.format(self.data_sent_humanised)
            info+='\nData Received: {}'.format(self.data_received_humanised)
            info+='\nUsed Memory: {}'.format(self.used_memory_humanised)

        return [info]

    def get_warnings(self):
        """Return empty list"""
        return []

    def get_alerts(self):
        """Return empty list"""
        return []

