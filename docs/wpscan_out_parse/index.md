<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1" />
<meta name="generator" content="pdoc 0.8.4" />
<title>wpscan_out_parse API documentation</title>
<meta name="description" content="WPScan Output Parser technical documentation." />
<link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/sanitize.min.css" integrity="sha256-PK9q560IAAa6WVRRh76LtCaI8pjTJ2z11v0miyNNjrs=" crossorigin>
<link rel="preload stylesheet" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/10up-sanitize.css/11.0.1/typography.min.css" integrity="sha256-7l/o7C8jubJiy74VsKTidCy1yBkRtiUGbVkYBylBqUg=" crossorigin>
<link rel="stylesheet preload" as="style" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/styles/github.min.css" crossorigin>
<style>:root{--highlight-color:#fe9}.flex{display:flex !important}body{line-height:1.5em}#content{padding:20px}#sidebar{padding:30px;overflow:hidden}#sidebar > *:last-child{margin-bottom:2cm}.http-server-breadcrumbs{font-size:130%;margin:0 0 15px 0}#footer{font-size:.75em;padding:5px 30px;border-top:1px solid #ddd;text-align:right}#footer p{margin:0 0 0 1em;display:inline-block}#footer p:last-child{margin-right:30px}h1,h2,h3,h4,h5{font-weight:300}h1{font-size:2.5em;line-height:1.1em}h2{font-size:1.75em;margin:1em 0 .50em 0}h3{font-size:1.4em;margin:25px 0 10px 0}h4{margin:0;font-size:105%}h1:target,h2:target,h3:target,h4:target,h5:target,h6:target{background:var(--highlight-color);padding:.2em 0}a{color:#058;text-decoration:none;transition:color .3s ease-in-out}a:hover{color:#e82}.title code{font-weight:bold}h2[id^="header-"]{margin-top:2em}.ident{color:#900}pre code{background:#f8f8f8;font-size:.8em;line-height:1.4em}code{background:#f2f2f1;padding:1px 4px;overflow-wrap:break-word}h1 code{background:transparent}pre{background:#f8f8f8;border:0;border-top:1px solid #ccc;border-bottom:1px solid #ccc;margin:1em 0;padding:1ex}#http-server-module-list{display:flex;flex-flow:column}#http-server-module-list div{display:flex}#http-server-module-list dt{min-width:10%}#http-server-module-list p{margin-top:0}.toc ul,#index{list-style-type:none;margin:0;padding:0}#index code{background:transparent}#index h3{border-bottom:1px solid #ddd}#index ul{padding:0}#index h4{margin-top:.6em;font-weight:bold}@media (min-width:200ex){#index .two-column{column-count:2}}@media (min-width:300ex){#index .two-column{column-count:3}}dl{margin-bottom:2em}dl dl:last-child{margin-bottom:4em}dd{margin:0 0 1em 3em}#header-classes + dl > dd{margin-bottom:3em}dd dd{margin-left:2em}dd p{margin:10px 0}.name{background:#eee;font-weight:bold;font-size:.85em;padding:5px 10px;display:inline-block;min-width:40%}.name:hover{background:#e0e0e0}dt:target .name{background:var(--highlight-color)}.name > span:first-child{white-space:nowrap}.name.class > span:nth-child(2){margin-left:.4em}.inherited{color:#999;border-left:5px solid #eee;padding-left:1em}.inheritance em{font-style:normal;font-weight:bold}.desc h2{font-weight:400;font-size:1.25em}.desc h3{font-size:1em}.desc dt code{background:inherit}.source summary,.git-link-div{color:#666;text-align:right;font-weight:400;font-size:.8em;text-transform:uppercase}.source summary > *{white-space:nowrap;cursor:pointer}.git-link{color:inherit;margin-left:1em}.source pre{max-height:500px;overflow:auto;margin:0}.source pre code{font-size:12px;overflow:visible}.hlist{list-style:none}.hlist li{display:inline}.hlist li:after{content:',\2002'}.hlist li:last-child:after{content:none}.hlist .hlist{display:inline;padding-left:1em}img{max-width:100%}td{padding:0 .5em}.admonition{padding:.1em .5em;margin-bottom:1em}.admonition-title{font-weight:bold}.admonition.note,.admonition.info,.admonition.important{background:#aef}.admonition.todo,.admonition.versionadded,.admonition.tip,.admonition.hint{background:#dfd}.admonition.warning,.admonition.versionchanged,.admonition.deprecated{background:#fd4}.admonition.error,.admonition.danger,.admonition.caution{background:lightpink}</style>
<style media="screen and (min-width: 700px)">@media screen and (min-width:700px){#sidebar{width:30%;height:100vh;overflow:auto;position:sticky;top:0}#content{width:70%;max-width:100ch;padding:3em 4em;border-left:1px solid #ddd}pre code{font-size:1em}.item .name{font-size:1em}main{display:flex;flex-direction:row-reverse;justify-content:flex-end}.toc ul ul,#index ul{padding-left:1.5em}.toc > ul > li{margin-top:.5em}}</style>
<style media="print">@media print{#sidebar h1{page-break-before:always}.source{display:none}}@media print{*{background:transparent !important;color:#000 !important;box-shadow:none !important;text-shadow:none !important}a[href]:after{content:" (" attr(href) ")";font-size:90%}a[href][title]:after{content:none}abbr[title]:after{content:" (" attr(title) ")"}.ir a:after,a[href^="javascript:"]:after,a[href^="#"]:after{content:""}pre,blockquote{border:1px solid #999;page-break-inside:avoid}thead{display:table-header-group}tr,img{page-break-inside:avoid}img{max-width:100% !important}@page{margin:0.5cm}p,h2,h3{orphans:3;widows:3}h1,h2,h3,h4,h5,h6{page-break-after:avoid}}</style>
<script defer src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/9.18.1/highlight.min.js" integrity="sha256-eOgo0OtLL4cdq7RdwRUiGKLX9XsIJ7nGhWEKbohmVAQ=" crossorigin></script>
<script>window.addEventListener('DOMContentLoaded', () => hljs.initHighlighting())</script>
</head>
<body>
<main>
<article id="content">
<header>
<h1 class="title">Package <code>wpscan_out_parse</code></h1>
</header>
<section id="section-intro">
<p>WPScan Output Parser technical documentation.</p>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">&#34;&#34;&#34;
WPScan Output Parser technical documentation.  



&#34;&#34;&#34;

VERSION=&#39;1.3&#39;

import json, re

###################### IMPORTS  ######################

from .parser import ( _Parser, _WPScanResults, _WPScanResultsSummaryRow, _CoreFinding, InterestingFinding, 
    WordPressVersion, Plugin, MainTheme, Theme, Timthumb, DBExport, User, Media, ConfigBackup, 
    VulnAPI, PasswordAttack, NotFullyConfigured, Banner, ScanStarted, ScanFinished )
from .formatter import build_message

####################### INTERFACE METHODS ####################

def parse_results_from_string(wpscan_output_string, false_positives_strings=None, show_all_details=False):
    &#34;&#34;&#34; Parse any WPScan output string. 
    
    - wpscan_output_string: WPScan output as string
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
    Return the results as dict object&#34;&#34;&#34;
    try:
        data=json.loads(wpscan_output_string)
    except ValueError: 
        parser=WPScanCliParser(wpscan_output_string, false_positives_strings)
    else:  
        parser=WPScanJsonParser(data, false_positives_strings, show_all_details)
    return (parser.get_results())

def parse_results_from_file(wpscan_output_file, false_positives_strings=None, show_all_details=False):
    &#34;&#34;&#34; Prse any WPScan output file. 
    
    - wpscan_output_file: Path to WPScan output file
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
     Return the results as dict object&#34;&#34;&#34;
    with open(wpscan_output_file, &#39;r&#39;, encoding=&#39;utf-8&#39;) as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(wpscan_out_string, false_positives_strings=false_positives_strings, show_all_details=show_all_details)
    
    return results

def format_results(results, format):
    &#34;&#34;&#34;
    Format the results dict into a &#34;html&#34;, &#34;cli&#34; or &#34;json&#34; string.  

    - results: resutlts dict objject  
    - format: in &#34;html&#34;, &#34;cli&#34; or &#34;json&#34;
    &#34;&#34;&#34;
    if format == &#39;json&#39;:
        return json.dumps(dict(results), indent=4)
    else:
        return build_message(dict(results), format=format)

####################  CLI PARSER ######################

class WPScanCliParser(_Parser):
    &#34;&#34;&#34;Main interface to parse WPScan CLI output.  

    - wpscan_output: WPScan output as string.  
    - false_positives_strings: List of false positive strings.  

    Once instanciated, wpscan_output is parsed and the following methods are accessible:  get_infos(), get_warnings(), get_alerts()

    &#34;&#34;&#34;
    
    def __init__(self, wpscan_output, false_positives_strings=None):
        
        if not wpscan_output: wpscan_output=&#39;&#39;
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=False)
        super().__init__(wpscan_output, **parser_config)
        self.infos, self.warnings, self.alerts = self.parse_cli(wpscan_output)

    def get_infos(self):
        &#34;&#34;&#34; Return all the parsed infos&#34;&#34;&#34;
        return self.infos

    def get_warnings(self):
        &#34;&#34;&#34; Return all the parsed warnings&#34;&#34;&#34;
        return self.warnings

    def get_alerts(self):
        &#34;&#34;&#34; Return all the parsed alerts&#34;&#34;&#34;
        return self.alerts

    def _parse_cli_toogle(self, line, warning_on, alert_on):
        # Color parsing
        if &#34;33m[!]&#34; in line: warning_on=True
        elif &#34;31m[!]&#34; in line: alert_on = True
        # No color parsing Warnings string are hard coded here
        elif &#34;[!]&#34; in line and any([m in line for m in [   
            &#34;The version is out of date&#34;,
            &#34;No WPVulnDB API Token given&#34;,
            &#34;You can get a free API token&#34;]]) :
            warning_on = True
        elif &#34;[!]&#34; in line :
            alert_on = True
        # Both method with color and no color apply supplementary proccessing 
        # Warning for insecure Wordpress and based on interesting findings strings
        if any(string in line for string in [&#39;Insecure&#39;]+InterestingFinding.INTERESTING_FINDING_WARNING_STRINGS ): 
            warning_on = True
        # Trigger alert based on interesting finding alert strings
        if any(string in line for string in InterestingFinding.INTERESTING_FINDING_ALERT_STRINGS ):
            alert_on=True
        # Lower voice of Vulnerabilities found but not plugin version
        if &#39;The version could not be determined&#39; in line and alert_on:
            alert_on = False  
            warning_on = True 
        return ((warning_on, alert_on))

    def _ignore_false_positives(self, infos, warnings, alerts):
        &#34;&#34;&#34;Process false positives&#34;&#34;&#34;
        for alert in warnings+alerts:
            if self.is_false_positive(alert):
                try: alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append(&#34;[False positive]\n{}&#34;.format(alert))

        return infos, warnings, alerts
    
    def parse_cli(self, wpscan_output):
        &#34;&#34;&#34; Parse the ( messages, warnings, alerts ) from WPScan CLI output string.  
        Return results as tuple( messages, warnings, alerts ).  &#34;&#34;&#34;
        # Init scan messages
        ( messages, warnings, alerts ) = ([],[],[])
        # Init messages toogles
        warning_on, alert_on = False, False
        message_lines=[] 
        current_message=&#34;&#34;

        # Every blank (&#34;&#34;) line will be considered as a message separator
        for line in wpscan_output.splitlines()+[&#34;&#34;]:

            # Parse all output lines and build infos, warnings and alerts
            line=line.strip()
            
            # Parse line
            warning_on, alert_on = self._parse_cli_toogle(line, warning_on, alert_on)

            # Remove colorization anyway after parsing
            line = re.sub(r&#39;(\x1b|\[[0-9][0-9]?m)&#39;,&#39;&#39;,line)
            # Append line to message. Handle the begin of the message case
            message_lines.append(line)

            # Build message
            current_message=&#39;\n&#39;.join([m for m in message_lines if m not in [&#34;&#34;,&#34;|&#34;]]).strip()

            # Message separator just a white line.
            # Only if the message if not empty. 
            if ( line.strip() not in [&#34;&#34;] or current_message.strip() == &#34;&#34; ) : 
                continue

            # End of the message

            # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
            if (alert_on or warning_on) and any(s in current_message for s in [&#39;vulnerabilities identified&#39;,&#39;vulnerability identified&#39;]) : 
                messages_separated=[]
                msg=[]
                for l in message_lines+[&#34;|&#34;]:
                    if l.strip() == &#34;|&#34;:
                        messages_separated.append(&#39;\n&#39;.join([ m for m in msg if m not in [&#34;&#34;,&#34;|&#34;]] ))
                        msg=[]
                    msg.append(l)

                # Append Vulnerabilities messages to ALERTS and other infos in one message
                vulnerabilities = [ m for m in messages_separated if &#39;| [!] Title&#39; in m.splitlines()[0] ]

                # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
                plugin_infos=&#39;\n&#39;.join([ m for m in messages_separated if &#39;| [!] Title&#39; not in m.splitlines()[0] ])
                
                if ( len([v for v in vulnerabilities if not self.is_false_positive(v)])&gt;0 and 
                    &#34;The version could not be determined&#34; in plugin_infos) :
                    warnings.append(plugin_infos+&#34;\nAll known vulnerabilities are listed&#34;)
                else:
                    messages.append(plugin_infos)

                if alert_on: alerts.extend(vulnerabilities)
                elif warning_on: warnings.extend(vulnerabilities)

            elif warning_on: warnings.append(current_message)
            else: messages.append(current_message)
            message_lines=[]
            current_message=&#34;&#34;
            # Reset Toogle Warning/Alert
            warning_on, alert_on = False, False

        return (self._ignore_false_positives( messages, warnings, alerts ))

    def get_error(self):
        if &#39;Scan Aborted&#39; in self.data:
            return &#39;WPScan failed: {}&#39;.format(&#39;\n&#39;.join(line for line in self.data.splitlines() if &#39;Scan Aborted&#39; in line))
        else:
            return None
        
    def get_results(self):
        &#34;&#34;&#34;
        Returns a dictionnary structure like: 
        ```
        {
        &#39;infos&#39;:[],
        &#39;warnings&#39;:[],
        &#39;alerts&#39;:[],
        &#39;summary&#39;:{
            &#39;table&#39;:None, 
            &#39;line&#39;:&#39;WPScan result summary: alerts={}, warnings={}, infos={}, error={}&#39;
            },
        &#39;error&#39;:None
        }   
        ```
        &#34;&#34;&#34;
        results = _WPScanResults()
        results[&#39;infos&#39;]=self.get_infos()
        results[&#39;warnings&#39;]=self.get_warnings()
        results[&#39;alerts&#39;]=self.get_alerts()
        results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
        results[&#39;error&#39;]=self.get_error()
        return dict(results)

#################### JSON PARSER ######################

class WPScanJsonParser(_Parser):
    &#34;&#34;&#34;Main interface to parse WPScan JSON data
    
    - data: The JSON structure of the WPScan output.    
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).  

    Once instanciated, the following methods are accessible: get_infos(), get_warnings(), get_alerts() 
    
    And the following properties are accessible:  
            version, main_theme, plugins, themes, interesting_findings, password_attack, 
            not_fully_configured, timthumbs, db_exports, users, medias, config_backups, 
            vuln_api, banner, scan_started, scan_finished
    &#34;&#34;&#34;
    
    def __init__(self, data, false_positives_strings=None, show_all_details=False):
        
        if not data: data={}
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=show_all_details)
        super().__init__(data, **parser_config)
        self.components=[]
        # Add WordPressVersion
        if &#39;version&#39; in data:
            self.version=WordPressVersion(data.get(&#39;version&#39;), **parser_config)
        else:
            self.version=None
        # Add MainTheme
        if &#39;main_theme&#39; in data:
            self.main_theme=MainTheme(data.get(&#39;main_theme&#39;), **parser_config)
        else:
            self.main_theme=None
        # Add Plugins
        if &#39;plugins&#39; in data:
            self.plugins=[Plugin(data.get(&#39;plugins&#39;).get(slug), **parser_config) for slug in data.get(&#39;plugins&#39;)]
        else:
            self.plugins=[]
        # Add Themes ; Make sure the main theme is not displayed twice
        if &#39;themes&#39; in data:
            self.themes=[Theme(data.get(&#39;themes&#39;).get(slug), **parser_config) for slug in data.get(&#39;themes&#39;) if not self.main_theme or slug!=self.main_theme.slug]
        else:
            self.themes=[]
        # Add Interesting findings
        if &#39;interesting_findings&#39; in data:
            self.interesting_findings=[InterestingFinding(finding, **parser_config) for finding in data.get(&#39;interesting_findings&#39;)]
        else:
            self.interesting_findings=[]
        # Add Timthumbs
        if &#39;timthumbs&#39; in data:
            self.timthumbs=[Timthumb(url, data.get(&#39;timthumbs&#39;).get(url), **parser_config) for url in data.get(&#39;timthumbs&#39;)]
        else:
            self.timthumbs=[]
        # Add DBExport
        if &#39;db_exports&#39; in data:
            self.db_exports=[DBExport(url, data.get(&#39;db_exports&#39;).get(url), **parser_config) for url in data.get(&#39;db_exports&#39;)]
        else:
            self.db_exports=[]
        # Add Users
        if &#39;users&#39; in data:
            self.users=[User(url, data.get(&#39;users&#39;).get(url), **parser_config) for url in data.get(&#39;users&#39;)]
        else:
            self.users=[]
        # Add Medias
        if &#39;medias&#39; in data:
            self.medias=[Media(url, data.get(&#39;medias&#39;).get(url), **parser_config) for url in data.get(&#39;medias&#39;)]
        else:
            self.medias=[]
        # Add Config backups
        if &#39;config_backups&#39; in data:
            self.config_backups=[ConfigBackup(url, data.get(&#39;config_backups&#39;).get(url), **parser_config) for url in data.get(&#39;config_backups&#39;)]
        else:
            self.config_backups=[]
        # Add VulnAPI 
        if &#39;vuln_api&#39; in data:
            self.vuln_api=VulnAPI(data.get(&#39;vuln_api&#39;), **parser_config)
        else:
            self.vuln_api=None
        # Add Password attack
        if data.get(&#39;password_attack&#39;, None):
            self.password_attack=PasswordAttack(data.get(&#39;password_attack&#39;), **parser_config)
        else: 
            self.password_attack=None
        # Add Not fully configured
        if data.get(&#39;not_fully_configured&#39;, None):
            self.not_fully_configured=NotFullyConfigured(data.get(&#39;not_fully_configured&#39;), **parser_config)
        else:
            self.not_fully_configured=None
        # Add 
        if data.get(&#39;banner&#39;, None):
            self.banner=Banner(data.get(&#39;banner&#39;), **parser_config)
        else:
            self.banner=None
        # Add ScanStarted
        if &#39;target_url&#39; in data:
            self.scan_started=ScanStarted(data, **parser_config)
        else:
            self.scan_started=None
        # Add ScanFinished
        if &#39;enlapsed&#39; in data:
            self.scan_finished=ScanFinished(data, **parser_config)
        else:
            self.scan_finished=None
        # Add Scan aborted error
        if data.get(&#39;scan_aborted&#39;, None):
            self.error = &#39;Scan Aborted: {}&#39;.format(data[&#39;scan_aborted&#39;])
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
        &#34;&#34;&#34;Get all infos from all components and add false positives as infos with &#34;[False positive]&#34; prefix&#34;&#34;&#34;
        infos=[]
        for component in self.components:
            infos.extend(component.get_infos())

            # If all vulns are ignored, add component message to infos
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically add wp item infos if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
                and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
                and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
                infos.extend(component_warnings)

            for alert in component.get_alerts()+component.get_warnings():
                if self.is_false_positive(alert):
                    infos.append(&#34;[False positive]\n&#34;+alert)

        return infos

    def get_warnings(self):
        &#34;&#34;&#34;Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored&#34;&#34;&#34;
        warnings=[]
        for component in self.components:
            # Ignore false positives warnings
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically remove wp item warning if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
                and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
                and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
                component_warnings=[]

            warnings.extend(component_warnings)
            
        return warnings

    def get_alerts(self):
        &#34;&#34;&#34;Get all alerts from all components and igore false positives&#34;&#34;&#34;
        alerts=[]
        for component in self.components:
            alerts.extend([ alert for alert in component.get_alerts() if not self.is_false_positive(alert) ])
        return alerts

    def get_results(self):
        results = _WPScanResults()
        results[&#39;infos&#39;]=self.get_infos()
        results[&#39;warnings&#39;]=self.get_warnings()
        results[&#39;alerts&#39;]=self.get_alerts()
        results[&#39;summary&#39;][&#39;table&#39;]=self.get_summary_list()
        results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
        results[&#39;error&#39;]=self.get_error()
        return dict(results)

    def get_core_findings(self):
        &#34;&#34;&#34; Get only core findings. Core findings appears in the table summary.  &#34;&#34;&#34;
        core=[]
        for component in self.components:
            if isinstance(component, _CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self):
        &#34;&#34;&#34;Return a list of dict with all plugins, vuls, and statuses.  &#34;&#34;&#34;
        summary_table=[]
        for component in self.get_core_findings():
            row=_WPScanResultsSummaryRow({
                &#39;Component&#39;: component.get_name(),
                &#39;Version&#39;: component.get_version(),
                &#39;Version State&#39;: component.get_version_status(),
                &#39;Vulnerabilities&#39;: component.get_vulnerabilities_string(),
                &#39;Status&#39;: component.get_status()
            })
            summary_table.append(dict(row))
        return summary_table

    def get_error(self):
        if self.error:
            return &#39;WPScan failed: {}&#39;.format(self.error)
        else:
            return None</code></pre>
</details>
</section>
<section>
<h2 class="section-title" id="header-submodules">Sub-modules</h2>
<dl>
<dt><code class="name"><a title="wpscan_out_parse.formatter" href="formatter.html">wpscan_out_parse.formatter</a></code></dt>
<dd>
<div class="desc"></div>
</dd>
<dt><code class="name"><a title="wpscan_out_parse.parser" href="parser.html">wpscan_out_parse.parser</a></code></dt>
<dd>
<div class="desc"></div>
</dd>
</dl>
</section>
<section>
</section>
<section>
<h2 class="section-title" id="header-functions">Functions</h2>
<dl>
<dt id="wpscan_out_parse.format_results"><code class="name flex">
<span>def <span class="ident">format_results</span></span>(<span>results, format)</span>
</code></dt>
<dd>
<div class="desc"><p>Format the results dict into a "html", "cli" or "json" string.
</p>
<ul>
<li>results: resutlts dict objject
</li>
<li>format: in "html", "cli" or "json"</li>
</ul></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def format_results(results, format):
    &#34;&#34;&#34;
    Format the results dict into a &#34;html&#34;, &#34;cli&#34; or &#34;json&#34; string.  

    - results: resutlts dict objject  
    - format: in &#34;html&#34;, &#34;cli&#34; or &#34;json&#34;
    &#34;&#34;&#34;
    if format == &#39;json&#39;:
        return json.dumps(dict(results), indent=4)
    else:
        return build_message(dict(results), format=format)</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.parse_results_from_file"><code class="name flex">
<span>def <span class="ident">parse_results_from_file</span></span>(<span>wpscan_output_file, false_positives_strings=None, show_all_details=False)</span>
</code></dt>
<dd>
<div class="desc"><p>Prse any WPScan output file. </p>
<ul>
<li>wpscan_output_file: Path to WPScan output file</li>
<li>false_positives_strings: List of false positive strings.
</li>
<li>show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.
</li>
</ul>
<p>Return the results as dict object</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def parse_results_from_file(wpscan_output_file, false_positives_strings=None, show_all_details=False):
    &#34;&#34;&#34; Prse any WPScan output file. 
    
    - wpscan_output_file: Path to WPScan output file
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
     Return the results as dict object&#34;&#34;&#34;
    with open(wpscan_output_file, &#39;r&#39;, encoding=&#39;utf-8&#39;) as wpscan_out:
        wpscan_out_string = wpscan_out.read()
        results = parse_results_from_string(wpscan_out_string, false_positives_strings=false_positives_strings, show_all_details=show_all_details)
    
    return results</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.parse_results_from_string"><code class="name flex">
<span>def <span class="ident">parse_results_from_string</span></span>(<span>wpscan_output_string, false_positives_strings=None, show_all_details=False)</span>
</code></dt>
<dd>
<div class="desc"><p>Parse any WPScan output string. </p>
<ul>
<li>wpscan_output_string: WPScan output as string</li>
<li>false_positives_strings: List of false positive strings.
</li>
<li>show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.
</li>
</ul>
<p>Return the results as dict object</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def parse_results_from_string(wpscan_output_string, false_positives_strings=None, show_all_details=False):
    &#34;&#34;&#34; Parse any WPScan output string. 
    
    - wpscan_output_string: WPScan output as string
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   
    
    Return the results as dict object&#34;&#34;&#34;
    try:
        data=json.loads(wpscan_output_string)
    except ValueError: 
        parser=WPScanCliParser(wpscan_output_string, false_positives_strings)
    else:  
        parser=WPScanJsonParser(data, false_positives_strings, show_all_details)
    return (parser.get_results())</code></pre>
</details>
</dd>
</dl>
</section>
<section>
<h2 class="section-title" id="header-classes">Classes</h2>
<dl>
<dt id="wpscan_out_parse.WPScanCliParser"><code class="flex name class">
<span>class <span class="ident">WPScanCliParser</span></span>
<span>(</span><span>wpscan_output, false_positives_strings=None)</span>
</code></dt>
<dd>
<div class="desc"><p>Main interface to parse WPScan CLI output.
</p>
<ul>
<li>wpscan_output: WPScan output as string.
</li>
<li>false_positives_strings: List of false positive strings.
</li>
</ul>
<p>Once instanciated, wpscan_output is parsed and the following methods are accessible:
get_infos(), get_warnings(), get_alerts()</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">class WPScanCliParser(_Parser):
    &#34;&#34;&#34;Main interface to parse WPScan CLI output.  

    - wpscan_output: WPScan output as string.  
    - false_positives_strings: List of false positive strings.  

    Once instanciated, wpscan_output is parsed and the following methods are accessible:  get_infos(), get_warnings(), get_alerts()

    &#34;&#34;&#34;
    
    def __init__(self, wpscan_output, false_positives_strings=None):
        
        if not wpscan_output: wpscan_output=&#39;&#39;
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=False)
        super().__init__(wpscan_output, **parser_config)
        self.infos, self.warnings, self.alerts = self.parse_cli(wpscan_output)

    def get_infos(self):
        &#34;&#34;&#34; Return all the parsed infos&#34;&#34;&#34;
        return self.infos

    def get_warnings(self):
        &#34;&#34;&#34; Return all the parsed warnings&#34;&#34;&#34;
        return self.warnings

    def get_alerts(self):
        &#34;&#34;&#34; Return all the parsed alerts&#34;&#34;&#34;
        return self.alerts

    def _parse_cli_toogle(self, line, warning_on, alert_on):
        # Color parsing
        if &#34;33m[!]&#34; in line: warning_on=True
        elif &#34;31m[!]&#34; in line: alert_on = True
        # No color parsing Warnings string are hard coded here
        elif &#34;[!]&#34; in line and any([m in line for m in [   
            &#34;The version is out of date&#34;,
            &#34;No WPVulnDB API Token given&#34;,
            &#34;You can get a free API token&#34;]]) :
            warning_on = True
        elif &#34;[!]&#34; in line :
            alert_on = True
        # Both method with color and no color apply supplementary proccessing 
        # Warning for insecure Wordpress and based on interesting findings strings
        if any(string in line for string in [&#39;Insecure&#39;]+InterestingFinding.INTERESTING_FINDING_WARNING_STRINGS ): 
            warning_on = True
        # Trigger alert based on interesting finding alert strings
        if any(string in line for string in InterestingFinding.INTERESTING_FINDING_ALERT_STRINGS ):
            alert_on=True
        # Lower voice of Vulnerabilities found but not plugin version
        if &#39;The version could not be determined&#39; in line and alert_on:
            alert_on = False  
            warning_on = True 
        return ((warning_on, alert_on))

    def _ignore_false_positives(self, infos, warnings, alerts):
        &#34;&#34;&#34;Process false positives&#34;&#34;&#34;
        for alert in warnings+alerts:
            if self.is_false_positive(alert):
                try: alerts.remove(alert)
                except ValueError:
                    warnings.remove(alert)
                infos.append(&#34;[False positive]\n{}&#34;.format(alert))

        return infos, warnings, alerts
    
    def parse_cli(self, wpscan_output):
        &#34;&#34;&#34; Parse the ( messages, warnings, alerts ) from WPScan CLI output string.  
        Return results as tuple( messages, warnings, alerts ).  &#34;&#34;&#34;
        # Init scan messages
        ( messages, warnings, alerts ) = ([],[],[])
        # Init messages toogles
        warning_on, alert_on = False, False
        message_lines=[] 
        current_message=&#34;&#34;

        # Every blank (&#34;&#34;) line will be considered as a message separator
        for line in wpscan_output.splitlines()+[&#34;&#34;]:

            # Parse all output lines and build infos, warnings and alerts
            line=line.strip()
            
            # Parse line
            warning_on, alert_on = self._parse_cli_toogle(line, warning_on, alert_on)

            # Remove colorization anyway after parsing
            line = re.sub(r&#39;(\x1b|\[[0-9][0-9]?m)&#39;,&#39;&#39;,line)
            # Append line to message. Handle the begin of the message case
            message_lines.append(line)

            # Build message
            current_message=&#39;\n&#39;.join([m for m in message_lines if m not in [&#34;&#34;,&#34;|&#34;]]).strip()

            # Message separator just a white line.
            # Only if the message if not empty. 
            if ( line.strip() not in [&#34;&#34;] or current_message.strip() == &#34;&#34; ) : 
                continue

            # End of the message

            # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
            if (alert_on or warning_on) and any(s in current_message for s in [&#39;vulnerabilities identified&#39;,&#39;vulnerability identified&#39;]) : 
                messages_separated=[]
                msg=[]
                for l in message_lines+[&#34;|&#34;]:
                    if l.strip() == &#34;|&#34;:
                        messages_separated.append(&#39;\n&#39;.join([ m for m in msg if m not in [&#34;&#34;,&#34;|&#34;]] ))
                        msg=[]
                    msg.append(l)

                # Append Vulnerabilities messages to ALERTS and other infos in one message
                vulnerabilities = [ m for m in messages_separated if &#39;| [!] Title&#39; in m.splitlines()[0] ]

                # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
                plugin_infos=&#39;\n&#39;.join([ m for m in messages_separated if &#39;| [!] Title&#39; not in m.splitlines()[0] ])
                
                if ( len([v for v in vulnerabilities if not self.is_false_positive(v)])&gt;0 and 
                    &#34;The version could not be determined&#34; in plugin_infos) :
                    warnings.append(plugin_infos+&#34;\nAll known vulnerabilities are listed&#34;)
                else:
                    messages.append(plugin_infos)

                if alert_on: alerts.extend(vulnerabilities)
                elif warning_on: warnings.extend(vulnerabilities)

            elif warning_on: warnings.append(current_message)
            else: messages.append(current_message)
            message_lines=[]
            current_message=&#34;&#34;
            # Reset Toogle Warning/Alert
            warning_on, alert_on = False, False

        return (self._ignore_false_positives( messages, warnings, alerts ))

    def get_error(self):
        if &#39;Scan Aborted&#39; in self.data:
            return &#39;WPScan failed: {}&#39;.format(&#39;\n&#39;.join(line for line in self.data.splitlines() if &#39;Scan Aborted&#39; in line))
        else:
            return None
        
    def get_results(self):
        &#34;&#34;&#34;
        Returns a dictionnary structure like: 
        ```
        {
        &#39;infos&#39;:[],
        &#39;warnings&#39;:[],
        &#39;alerts&#39;:[],
        &#39;summary&#39;:{
            &#39;table&#39;:None, 
            &#39;line&#39;:&#39;WPScan result summary: alerts={}, warnings={}, infos={}, error={}&#39;
            },
        &#39;error&#39;:None
        }   
        ```
        &#34;&#34;&#34;
        results = _WPScanResults()
        results[&#39;infos&#39;]=self.get_infos()
        results[&#39;warnings&#39;]=self.get_warnings()
        results[&#39;alerts&#39;]=self.get_alerts()
        results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
        results[&#39;error&#39;]=self.get_error()
        return dict(results)</code></pre>
</details>
<h3>Ancestors</h3>
<ul class="hlist">
<li>wpscan_out_parse.parser._Parser</li>
<li>wpscan_out_parse.parser._Component</li>
<li>abc.ABC</li>
</ul>
<h3>Methods</h3>
<dl>
<dt id="wpscan_out_parse.WPScanCliParser.get_alerts"><code class="name flex">
<span>def <span class="ident">get_alerts</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return all the parsed alerts</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_alerts(self):
    &#34;&#34;&#34; Return all the parsed alerts&#34;&#34;&#34;
    return self.alerts</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanCliParser.get_error"><code class="name flex">
<span>def <span class="ident">get_error</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return any error or None if no errors</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_error(self):
    if &#39;Scan Aborted&#39; in self.data:
        return &#39;WPScan failed: {}&#39;.format(&#39;\n&#39;.join(line for line in self.data.splitlines() if &#39;Scan Aborted&#39; in line))
    else:
        return None</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanCliParser.get_infos"><code class="name flex">
<span>def <span class="ident">get_infos</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return all the parsed infos</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_infos(self):
    &#34;&#34;&#34; Return all the parsed infos&#34;&#34;&#34;
    return self.infos</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanCliParser.get_results"><code class="name flex">
<span>def <span class="ident">get_results</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Returns a dictionnary structure like: </p>
<pre><code>{
'infos':[],
'warnings':[],
'alerts':[],
'summary':{
    'table':None, 
    'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
    },
'error':None
}   
</code></pre></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_results(self):
    &#34;&#34;&#34;
    Returns a dictionnary structure like: 
    ```
    {
    &#39;infos&#39;:[],
    &#39;warnings&#39;:[],
    &#39;alerts&#39;:[],
    &#39;summary&#39;:{
        &#39;table&#39;:None, 
        &#39;line&#39;:&#39;WPScan result summary: alerts={}, warnings={}, infos={}, error={}&#39;
        },
    &#39;error&#39;:None
    }   
    ```
    &#34;&#34;&#34;
    results = _WPScanResults()
    results[&#39;infos&#39;]=self.get_infos()
    results[&#39;warnings&#39;]=self.get_warnings()
    results[&#39;alerts&#39;]=self.get_alerts()
    results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
    results[&#39;error&#39;]=self.get_error()
    return dict(results)</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanCliParser.get_warnings"><code class="name flex">
<span>def <span class="ident">get_warnings</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return all the parsed warnings</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_warnings(self):
    &#34;&#34;&#34; Return all the parsed warnings&#34;&#34;&#34;
    return self.warnings</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanCliParser.parse_cli"><code class="name flex">
<span>def <span class="ident">parse_cli</span></span>(<span>self, wpscan_output)</span>
</code></dt>
<dd>
<div class="desc"><p>Parse the ( messages, warnings, alerts ) from WPScan CLI output string.<br>
Return results as tuple( messages, warnings, alerts ).</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def parse_cli(self, wpscan_output):
    &#34;&#34;&#34; Parse the ( messages, warnings, alerts ) from WPScan CLI output string.  
    Return results as tuple( messages, warnings, alerts ).  &#34;&#34;&#34;
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    # Init messages toogles
    warning_on, alert_on = False, False
    message_lines=[] 
    current_message=&#34;&#34;

    # Every blank (&#34;&#34;) line will be considered as a message separator
    for line in wpscan_output.splitlines()+[&#34;&#34;]:

        # Parse all output lines and build infos, warnings and alerts
        line=line.strip()
        
        # Parse line
        warning_on, alert_on = self._parse_cli_toogle(line, warning_on, alert_on)

        # Remove colorization anyway after parsing
        line = re.sub(r&#39;(\x1b|\[[0-9][0-9]?m)&#39;,&#39;&#39;,line)
        # Append line to message. Handle the begin of the message case
        message_lines.append(line)

        # Build message
        current_message=&#39;\n&#39;.join([m for m in message_lines if m not in [&#34;&#34;,&#34;|&#34;]]).strip()

        # Message separator just a white line.
        # Only if the message if not empty. 
        if ( line.strip() not in [&#34;&#34;] or current_message.strip() == &#34;&#34; ) : 
            continue

        # End of the message

        # Post process message to separate ALERTS into different messages of same status and add rest of the infos to warnings
        if (alert_on or warning_on) and any(s in current_message for s in [&#39;vulnerabilities identified&#39;,&#39;vulnerability identified&#39;]) : 
            messages_separated=[]
            msg=[]
            for l in message_lines+[&#34;|&#34;]:
                if l.strip() == &#34;|&#34;:
                    messages_separated.append(&#39;\n&#39;.join([ m for m in msg if m not in [&#34;&#34;,&#34;|&#34;]] ))
                    msg=[]
                msg.append(l)

            # Append Vulnerabilities messages to ALERTS and other infos in one message
            vulnerabilities = [ m for m in messages_separated if &#39;| [!] Title&#39; in m.splitlines()[0] ]

            # Add the plugin infos to warnings or false positive if every vulnerabilities are ignore
            plugin_infos=&#39;\n&#39;.join([ m for m in messages_separated if &#39;| [!] Title&#39; not in m.splitlines()[0] ])
            
            if ( len([v for v in vulnerabilities if not self.is_false_positive(v)])&gt;0 and 
                &#34;The version could not be determined&#34; in plugin_infos) :
                warnings.append(plugin_infos+&#34;\nAll known vulnerabilities are listed&#34;)
            else:
                messages.append(plugin_infos)

            if alert_on: alerts.extend(vulnerabilities)
            elif warning_on: warnings.extend(vulnerabilities)

        elif warning_on: warnings.append(current_message)
        else: messages.append(current_message)
        message_lines=[]
        current_message=&#34;&#34;
        # Reset Toogle Warning/Alert
        warning_on, alert_on = False, False

    return (self._ignore_false_positives( messages, warnings, alerts ))</code></pre>
</details>
</dd>
</dl>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser"><code class="flex name class">
<span>class <span class="ident">WPScanJsonParser</span></span>
<span>(</span><span>data, false_positives_strings=None, show_all_details=False)</span>
</code></dt>
<dd>
<div class="desc"><p>Main interface to parse WPScan JSON data</p>
<ul>
<li>data: The JSON structure of the WPScan output.
</li>
<li>false_positives_strings: List of false positive strings.
</li>
<li>show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).
</li>
</ul>
<p>Once instanciated, the following methods are accessible: get_infos(), get_warnings(), get_alerts() </p>
<p>And the following properties are accessible:<br>
version, main_theme, plugins, themes, interesting_findings, password_attack,
not_fully_configured, timthumbs, db_exports, users, medias, config_backups,
vuln_api, banner, scan_started, scan_finished</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">class WPScanJsonParser(_Parser):
    &#34;&#34;&#34;Main interface to parse WPScan JSON data
    
    - data: The JSON structure of the WPScan output.    
    - false_positives_strings: List of false positive strings.  
    - show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).  

    Once instanciated, the following methods are accessible: get_infos(), get_warnings(), get_alerts() 
    
    And the following properties are accessible:  
            version, main_theme, plugins, themes, interesting_findings, password_attack, 
            not_fully_configured, timthumbs, db_exports, users, medias, config_backups, 
            vuln_api, banner, scan_started, scan_finished
    &#34;&#34;&#34;
    
    def __init__(self, data, false_positives_strings=None, show_all_details=False):
        
        if not data: data={}
        # _Parser config: false positives string and verbosity (not available with cli parser)
        parser_config=dict(false_positives_strings=false_positives_strings, show_all_details=show_all_details)
        super().__init__(data, **parser_config)
        self.components=[]
        # Add WordPressVersion
        if &#39;version&#39; in data:
            self.version=WordPressVersion(data.get(&#39;version&#39;), **parser_config)
        else:
            self.version=None
        # Add MainTheme
        if &#39;main_theme&#39; in data:
            self.main_theme=MainTheme(data.get(&#39;main_theme&#39;), **parser_config)
        else:
            self.main_theme=None
        # Add Plugins
        if &#39;plugins&#39; in data:
            self.plugins=[Plugin(data.get(&#39;plugins&#39;).get(slug), **parser_config) for slug in data.get(&#39;plugins&#39;)]
        else:
            self.plugins=[]
        # Add Themes ; Make sure the main theme is not displayed twice
        if &#39;themes&#39; in data:
            self.themes=[Theme(data.get(&#39;themes&#39;).get(slug), **parser_config) for slug in data.get(&#39;themes&#39;) if not self.main_theme or slug!=self.main_theme.slug]
        else:
            self.themes=[]
        # Add Interesting findings
        if &#39;interesting_findings&#39; in data:
            self.interesting_findings=[InterestingFinding(finding, **parser_config) for finding in data.get(&#39;interesting_findings&#39;)]
        else:
            self.interesting_findings=[]
        # Add Timthumbs
        if &#39;timthumbs&#39; in data:
            self.timthumbs=[Timthumb(url, data.get(&#39;timthumbs&#39;).get(url), **parser_config) for url in data.get(&#39;timthumbs&#39;)]
        else:
            self.timthumbs=[]
        # Add DBExport
        if &#39;db_exports&#39; in data:
            self.db_exports=[DBExport(url, data.get(&#39;db_exports&#39;).get(url), **parser_config) for url in data.get(&#39;db_exports&#39;)]
        else:
            self.db_exports=[]
        # Add Users
        if &#39;users&#39; in data:
            self.users=[User(url, data.get(&#39;users&#39;).get(url), **parser_config) for url in data.get(&#39;users&#39;)]
        else:
            self.users=[]
        # Add Medias
        if &#39;medias&#39; in data:
            self.medias=[Media(url, data.get(&#39;medias&#39;).get(url), **parser_config) for url in data.get(&#39;medias&#39;)]
        else:
            self.medias=[]
        # Add Config backups
        if &#39;config_backups&#39; in data:
            self.config_backups=[ConfigBackup(url, data.get(&#39;config_backups&#39;).get(url), **parser_config) for url in data.get(&#39;config_backups&#39;)]
        else:
            self.config_backups=[]
        # Add VulnAPI 
        if &#39;vuln_api&#39; in data:
            self.vuln_api=VulnAPI(data.get(&#39;vuln_api&#39;), **parser_config)
        else:
            self.vuln_api=None
        # Add Password attack
        if data.get(&#39;password_attack&#39;, None):
            self.password_attack=PasswordAttack(data.get(&#39;password_attack&#39;), **parser_config)
        else: 
            self.password_attack=None
        # Add Not fully configured
        if data.get(&#39;not_fully_configured&#39;, None):
            self.not_fully_configured=NotFullyConfigured(data.get(&#39;not_fully_configured&#39;), **parser_config)
        else:
            self.not_fully_configured=None
        # Add 
        if data.get(&#39;banner&#39;, None):
            self.banner=Banner(data.get(&#39;banner&#39;), **parser_config)
        else:
            self.banner=None
        # Add ScanStarted
        if &#39;target_url&#39; in data:
            self.scan_started=ScanStarted(data, **parser_config)
        else:
            self.scan_started=None
        # Add ScanFinished
        if &#39;enlapsed&#39; in data:
            self.scan_finished=ScanFinished(data, **parser_config)
        else:
            self.scan_finished=None
        # Add Scan aborted error
        if data.get(&#39;scan_aborted&#39;, None):
            self.error = &#39;Scan Aborted: {}&#39;.format(data[&#39;scan_aborted&#39;])
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
        &#34;&#34;&#34;Get all infos from all components and add false positives as infos with &#34;[False positive]&#34; prefix&#34;&#34;&#34;
        infos=[]
        for component in self.components:
            infos.extend(component.get_infos())

            # If all vulns are ignored, add component message to infos
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically add wp item infos if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
                and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
                and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
                infos.extend(component_warnings)

            for alert in component.get_alerts()+component.get_warnings():
                if self.is_false_positive(alert):
                    infos.append(&#34;[False positive]\n&#34;+alert)

        return infos

    def get_warnings(self):
        &#34;&#34;&#34;Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored&#34;&#34;&#34;
        warnings=[]
        for component in self.components:
            # Ignore false positives warnings
            component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
            # Automatically remove wp item warning if all vuln are ignored and component does not present another issue
            if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
                and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
                and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
                component_warnings=[]

            warnings.extend(component_warnings)
            
        return warnings

    def get_alerts(self):
        &#34;&#34;&#34;Get all alerts from all components and igore false positives&#34;&#34;&#34;
        alerts=[]
        for component in self.components:
            alerts.extend([ alert for alert in component.get_alerts() if not self.is_false_positive(alert) ])
        return alerts

    def get_results(self):
        results = _WPScanResults()
        results[&#39;infos&#39;]=self.get_infos()
        results[&#39;warnings&#39;]=self.get_warnings()
        results[&#39;alerts&#39;]=self.get_alerts()
        results[&#39;summary&#39;][&#39;table&#39;]=self.get_summary_list()
        results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
        results[&#39;error&#39;]=self.get_error()
        return dict(results)

    def get_core_findings(self):
        &#34;&#34;&#34; Get only core findings. Core findings appears in the table summary.  &#34;&#34;&#34;
        core=[]
        for component in self.components:
            if isinstance(component, _CoreFinding):
                core.append(component)
        return core

    def get_summary_list(self):
        &#34;&#34;&#34;Return a list of dict with all plugins, vuls, and statuses.  &#34;&#34;&#34;
        summary_table=[]
        for component in self.get_core_findings():
            row=_WPScanResultsSummaryRow({
                &#39;Component&#39;: component.get_name(),
                &#39;Version&#39;: component.get_version(),
                &#39;Version State&#39;: component.get_version_status(),
                &#39;Vulnerabilities&#39;: component.get_vulnerabilities_string(),
                &#39;Status&#39;: component.get_status()
            })
            summary_table.append(dict(row))
        return summary_table

    def get_error(self):
        if self.error:
            return &#39;WPScan failed: {}&#39;.format(self.error)
        else:
            return None</code></pre>
</details>
<h3>Ancestors</h3>
<ul class="hlist">
<li>wpscan_out_parse.parser._Parser</li>
<li>wpscan_out_parse.parser._Component</li>
<li>abc.ABC</li>
</ul>
<h3>Methods</h3>
<dl>
<dt id="wpscan_out_parse.WPScanJsonParser.get_alerts"><code class="name flex">
<span>def <span class="ident">get_alerts</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Get all alerts from all components and igore false positives</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_alerts(self):
    &#34;&#34;&#34;Get all alerts from all components and igore false positives&#34;&#34;&#34;
    alerts=[]
    for component in self.components:
        alerts.extend([ alert for alert in component.get_alerts() if not self.is_false_positive(alert) ])
    return alerts</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_core_findings"><code class="name flex">
<span>def <span class="ident">get_core_findings</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Get only core findings. Core findings appears in the table summary.</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_core_findings(self):
    &#34;&#34;&#34; Get only core findings. Core findings appears in the table summary.  &#34;&#34;&#34;
    core=[]
    for component in self.components:
        if isinstance(component, _CoreFinding):
            core.append(component)
    return core</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_error"><code class="name flex">
<span>def <span class="ident">get_error</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return any error or None if no errors</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_error(self):
    if self.error:
        return &#39;WPScan failed: {}&#39;.format(self.error)
    else:
        return None</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_infos"><code class="name flex">
<span>def <span class="ident">get_infos</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Get all infos from all components and add false positives as infos with "[False positive]" prefix</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_infos(self):
    &#34;&#34;&#34;Get all infos from all components and add false positives as infos with &#34;[False positive]&#34; prefix&#34;&#34;&#34;
    infos=[]
    for component in self.components:
        infos.extend(component.get_infos())

        # If all vulns are ignored, add component message to infos
        component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
        # Automatically add wp item infos if all vuln are ignored and component does not present another issue
        if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
            and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
            and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
            infos.extend(component_warnings)

        for alert in component.get_alerts()+component.get_warnings():
            if self.is_false_positive(alert):
                infos.append(&#34;[False positive]\n&#34;+alert)

    return infos</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_results"><code class="name flex">
<span>def <span class="ident">get_results</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Returns a dictionnary structure like: </p>
<pre><code>{
'infos':[],
'warnings':[],
'alerts':[],
'summary':{
    'table':[
        {
            'Component': None,
            'Version': None,
            'Version State': None,
            'Vulnerabilities': None,
            'Status': None
        },
        ...
    ], 
    'line':'WPScan result summary: alerts={}, warnings={}, infos={}, error={}'
    },
'error':None
}   
</code></pre></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_results(self):
    results = _WPScanResults()
    results[&#39;infos&#39;]=self.get_infos()
    results[&#39;warnings&#39;]=self.get_warnings()
    results[&#39;alerts&#39;]=self.get_alerts()
    results[&#39;summary&#39;][&#39;table&#39;]=self.get_summary_list()
    results[&#39;summary&#39;][&#39;line&#39;]=self.get_summary_line()
    results[&#39;error&#39;]=self.get_error()
    return dict(results)</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_summary_list"><code class="name flex">
<span>def <span class="ident">get_summary_list</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Return a list of dict with all plugins, vuls, and statuses.</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_summary_list(self):
    &#34;&#34;&#34;Return a list of dict with all plugins, vuls, and statuses.  &#34;&#34;&#34;
    summary_table=[]
    for component in self.get_core_findings():
        row=_WPScanResultsSummaryRow({
            &#39;Component&#39;: component.get_name(),
            &#39;Version&#39;: component.get_version(),
            &#39;Version State&#39;: component.get_version_status(),
            &#39;Vulnerabilities&#39;: component.get_vulnerabilities_string(),
            &#39;Status&#39;: component.get_status()
        })
        summary_table.append(dict(row))
    return summary_table</code></pre>
</details>
</dd>
<dt id="wpscan_out_parse.WPScanJsonParser.get_warnings"><code class="name flex">
<span>def <span class="ident">get_warnings</span></span>(<span>self)</span>
</code></dt>
<dd>
<div class="desc"><p>Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored</p></div>
<details class="source">
<summary>
<span>Expand source code</span>
</summary>
<pre><code class="python">def get_warnings(self):
    &#34;&#34;&#34;Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored&#34;&#34;&#34;
    warnings=[]
    for component in self.components:
        # Ignore false positives warnings
        component_warnings=[ warning for warning in component.get_warnings() if not self.is_false_positive(warning) ]
        # Automatically remove wp item warning if all vuln are ignored and component does not present another issue
        if ( len(component_warnings)==1 and &#39;The version could not be determined&#39; in component_warnings[0] 
            and not &#34;Directory listing is enabled&#34; in component_warnings[0] 
            and not &#34;An error log file has been found&#34; in component_warnings[0] ) :
            component_warnings=[]

        warnings.extend(component_warnings)
        
    return warnings</code></pre>
</details>
</dd>
</dl>
</dd>
</dl>
</section>
</article>
<nav id="sidebar">
<h1>Index</h1>
<div class="toc">
<ul></ul>
</div>
<ul id="index">
<li><h3><a href="#header-submodules">Sub-modules</a></h3>
<ul>
<li><code><a title="wpscan_out_parse.formatter" href="formatter.html">wpscan_out_parse.formatter</a></code></li>
<li><code><a title="wpscan_out_parse.parser" href="parser.html">wpscan_out_parse.parser</a></code></li>
</ul>
</li>
<li><h3><a href="#header-functions">Functions</a></h3>
<ul class="">
<li><code><a title="wpscan_out_parse.format_results" href="#wpscan_out_parse.format_results">format_results</a></code></li>
<li><code><a title="wpscan_out_parse.parse_results_from_file" href="#wpscan_out_parse.parse_results_from_file">parse_results_from_file</a></code></li>
<li><code><a title="wpscan_out_parse.parse_results_from_string" href="#wpscan_out_parse.parse_results_from_string">parse_results_from_string</a></code></li>
</ul>
</li>
<li><h3><a href="#header-classes">Classes</a></h3>
<ul>
<li>
<h4><code><a title="wpscan_out_parse.WPScanCliParser" href="#wpscan_out_parse.WPScanCliParser">WPScanCliParser</a></code></h4>
<ul class="two-column">
<li><code><a title="wpscan_out_parse.WPScanCliParser.get_alerts" href="#wpscan_out_parse.WPScanCliParser.get_alerts">get_alerts</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanCliParser.get_error" href="#wpscan_out_parse.WPScanCliParser.get_error">get_error</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanCliParser.get_infos" href="#wpscan_out_parse.WPScanCliParser.get_infos">get_infos</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanCliParser.get_results" href="#wpscan_out_parse.WPScanCliParser.get_results">get_results</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanCliParser.get_warnings" href="#wpscan_out_parse.WPScanCliParser.get_warnings">get_warnings</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanCliParser.parse_cli" href="#wpscan_out_parse.WPScanCliParser.parse_cli">parse_cli</a></code></li>
</ul>
</li>
<li>
<h4><code><a title="wpscan_out_parse.WPScanJsonParser" href="#wpscan_out_parse.WPScanJsonParser">WPScanJsonParser</a></code></h4>
<ul class="two-column">
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_alerts" href="#wpscan_out_parse.WPScanJsonParser.get_alerts">get_alerts</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_core_findings" href="#wpscan_out_parse.WPScanJsonParser.get_core_findings">get_core_findings</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_error" href="#wpscan_out_parse.WPScanJsonParser.get_error">get_error</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_infos" href="#wpscan_out_parse.WPScanJsonParser.get_infos">get_infos</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_results" href="#wpscan_out_parse.WPScanJsonParser.get_results">get_results</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_summary_list" href="#wpscan_out_parse.WPScanJsonParser.get_summary_list">get_summary_list</a></code></li>
<li><code><a title="wpscan_out_parse.WPScanJsonParser.get_warnings" href="#wpscan_out_parse.WPScanJsonParser.get_warnings">get_warnings</a></code></li>
</ul>
</li>
</ul>
</li>
</ul>
</nav>
</main>
<footer id="footer">
<p>Generated by <a href="https://pdoc3.github.io/pdoc"><cite>pdoc</cite> 0.8.4</a>.</p>
</footer>
</body>
</html>
