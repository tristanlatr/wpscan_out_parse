---
description: |
    API documentation for modules: wpscan_out_parse, wpscan_out_parse.formatter, wpscan_out_parse.parser.

lang: en

classoption: oneside
geometry: margin=1in
papersize: a4

linkcolor: blue
links-as-notes: true
...


    
# Module `wpscan_out_parse` {#wpscan_out_parse}

WPScan Output Parser technical documentation.


    
## Sub-modules

* [wpscan_out_parse.formatter](#wpscan_out_parse.formatter)
* [wpscan_out_parse.parser](#wpscan_out_parse.parser)



    
## Functions


    
### Function `format_results` {#wpscan_out_parse.format_results}




>     def format_results(
>         results,
>         format
>     )


Format the results dict into a "html", "cli" or "json" string.  

- results: resutlts dict objject  
- format: in "html", "cli" or "json"

    
### Function `parse_results_from_file` {#wpscan_out_parse.parse_results_from_file}




>     def parse_results_from_file(
>         wpscan_output_file,
>         false_positives_strings=None,
>         show_all_details=False
>     )


Prse any WPScan output file. 

- wpscan_output_file: Path to WPScan output file
- false_positives_strings: List of false positive strings.  
- show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   

 Return the results as dict object

    
### Function `parse_results_from_string` {#wpscan_out_parse.parse_results_from_string}




>     def parse_results_from_string(
>         wpscan_output_string,
>         false_positives_strings=None,
>         show_all_details=False
>     )


Parse any WPScan output string. 

- wpscan_output_string: WPScan output as string
- false_positives_strings: List of false positive strings.  
- show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc). Only with JSON output.   

Return the results as dict object


    
## Classes


    
### Class `WPScanCliParser` {#wpscan_out_parse.WPScanCliParser}




>     class WPScanCliParser(
>         wpscan_output,
>         false_positives_strings=None
>     )


Main interface to parse WPScan CLI output.  

- wpscan_output: WPScan output as string.  
- false_positives_strings: List of false positive strings.  

Once instanciated, wpscan_output is parsed and the following methods are accessible:  get_infos(), get_warnings(), get_alerts()


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Parser](#wpscan_out_parse.parser._Parser)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.WPScanCliParser.get_alerts}




>     def get_alerts(
>         self
>     )


Return all the parsed alerts

    
##### Method `get_error` {#wpscan_out_parse.WPScanCliParser.get_error}




>     def get_error(
>         self
>     )


Return any error or None if no errors

    
##### Method `get_infos` {#wpscan_out_parse.WPScanCliParser.get_infos}




>     def get_infos(
>         self
>     )


Return all the parsed infos

    
##### Method `get_results` {#wpscan_out_parse.WPScanCliParser.get_results}




>     def get_results(
>         self
>     )


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

    
##### Method `get_warnings` {#wpscan_out_parse.WPScanCliParser.get_warnings}




>     def get_warnings(
>         self
>     )


Return all the parsed warnings

    
##### Method `parse_cli` {#wpscan_out_parse.WPScanCliParser.parse_cli}




>     def parse_cli(
>         self,
>         wpscan_output
>     )


Parse the ( messages, warnings, alerts ) from WPScan CLI output string.  
Return results as tuple( messages, warnings, alerts ).

    
### Class `WPScanJsonParser` {#wpscan_out_parse.WPScanJsonParser}




>     class WPScanJsonParser(
>         data,
>         false_positives_strings=None,
>         show_all_details=False
>     )


Main interface to parse WPScan JSON data

- data: The JSON structure of the WPScan output.    
- false_positives_strings: List of false positive strings.  
- show_all_details: Boolean, enable to show all wpscan infos (found by, confidence, etc).  

Once instanciated, the following methods are accessible: get_infos(), get_warnings(), get_alerts() 

And the following properties are accessible:  
        version, main_theme, plugins, themes, interesting_findings, password_attack, 
        not_fully_configured, timthumbs, db_exports, users, medias, config_backups, 
        vuln_api, banner, scan_started, scan_finished


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Parser](#wpscan_out_parse.parser._Parser)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.WPScanJsonParser.get_alerts}




>     def get_alerts(
>         self
>     )


Get all alerts from all components and igore false positives

    
##### Method `get_core_findings` {#wpscan_out_parse.WPScanJsonParser.get_core_findings}




>     def get_core_findings(
>         self
>     )


Get only core findings. Core findings appears in the table summary.

    
##### Method `get_error` {#wpscan_out_parse.WPScanJsonParser.get_error}




>     def get_error(
>         self
>     )


Return any error or None if no errors

    
##### Method `get_infos` {#wpscan_out_parse.WPScanJsonParser.get_infos}




>     def get_infos(
>         self
>     )


Get all infos from all components and add false positives as infos with "[False positive]" prefix

    
##### Method `get_results` {#wpscan_out_parse.WPScanJsonParser.get_results}




>     def get_results(
>         self
>     )


Returns a dictionnary structure like: 
```
{
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
```

    
##### Method `get_summary_list` {#wpscan_out_parse.WPScanJsonParser.get_summary_list}




>     def get_summary_list(
>         self
>     )


Return a list of dict with all plugins, vuls, and statuses.

    
##### Method `get_warnings` {#wpscan_out_parse.WPScanJsonParser.get_warnings}




>     def get_warnings(
>         self
>     )


Get all warnings from all components and igore false positives and automatically remove special warning if all vuln are ignored



    
# Module `wpscan_out_parse.formatter` {#wpscan_out_parse.formatter}






    
## Functions


    
### Function `build_message` {#wpscan_out_parse.formatter.build_message}




>     def build_message(
>         results,
>         warnings=True,
>         infos=True,
>         format='cli'
>     )


Build mail message text base on report and warnngs and info switch

    
### Function `format_issues` {#wpscan_out_parse.formatter.format_issues}




>     def format_issues(
>         title,
>         issues,
>         format='cli',
>         apply_br_tab_replace_on_issues=True
>     )


Format one block of issues to text with the title

    
### Function `format_summary_ascii_table` {#wpscan_out_parse.formatter.format_summary_ascii_table}




>     def format_summary_ascii_table(
>         table,
>         line
>     )


Return a nice string table
Author: Thierry Husson - Use it as you want but don't blame me.

    
### Function `format_summary_html` {#wpscan_out_parse.formatter.format_summary_html}




>     def format_summary_html(
>         table,
>         line
>     )




    
### Function `replace` {#wpscan_out_parse.formatter.replace}




>     def replace(
>         text,
>         conditions
>     )


Multiple replacements helper method.  Stolen on the web




    
# Module `wpscan_out_parse.parser` {#wpscan_out_parse.parser}







    
## Classes


    
### Class `Banner` {#wpscan_out_parse.parser.Banner}




>     class Banner(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.Banner.get_alerts}




>     def get_alerts(
>         self
>     )


Return empty list

    
##### Method `get_infos` {#wpscan_out_parse.parser.Banner.get_infos}




>     def get_infos(
>         self
>     )


Return the component informations as a list of strings.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Banner.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `ConfigBackup` {#wpscan_out_parse.parser.ConfigBackup}




>     class ConfigBackup(
>         url,
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.ConfigBackup.get_alerts}




>     def get_alerts(
>         self
>     )


Return 1 Config Backup alert

    
##### Method `get_infos` {#wpscan_out_parse.parser.ConfigBackup.get_infos}




>     def get_infos(
>         self
>     )


Return empty list

    
##### Method `get_name` {#wpscan_out_parse.parser.ConfigBackup.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.ConfigBackup.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `DBExport` {#wpscan_out_parse.parser.DBExport}




>     class DBExport(
>         url,
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.DBExport.get_alerts}




>     def get_alerts(
>         self
>     )


Return 1 DBExport alert

    
##### Method `get_infos` {#wpscan_out_parse.parser.DBExport.get_infos}




>     def get_infos(
>         self
>     )


Return empty list

    
##### Method `get_name` {#wpscan_out_parse.parser.DBExport.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.DBExport.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `InterestingFinding` {#wpscan_out_parse.parser.InterestingFinding}




>     class InterestingFinding(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb>  
Warnings and Alerts strings are from <https://github.com/wpscanteam/wpscan/blob/master/app/models/interesting_finding.rb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)



    
#### Class variables


    
##### Variable `INTERESTING_FINDING_ALERT_STRINGS` {#wpscan_out_parse.parser.InterestingFinding.INTERESTING_FINDING_ALERT_STRINGS}






    
##### Variable `INTERESTING_FINDING_WARNING_STRINGS` {#wpscan_out_parse.parser.InterestingFinding.INTERESTING_FINDING_WARNING_STRINGS}









    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.InterestingFinding.get_alerts}




>     def get_alerts(
>         self
>     )


Return list of alerts if finding match ALERT string

    
##### Method `get_infos` {#wpscan_out_parse.parser.InterestingFinding.get_infos}




>     def get_infos(
>         self
>     )


Return 1 info or 0 if finding is a warning or an alert

    
##### Method `get_warnings` {#wpscan_out_parse.parser.InterestingFinding.get_warnings}




>     def get_warnings(
>         self
>     )


Return list of warnings if finding match warning string

    
### Class `MainTheme` {#wpscan_out_parse.parser.MainTheme}




>     class MainTheme(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser.Theme](#wpscan_out_parse.parser.Theme)
* [wpscan_out_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_infos` {#wpscan_out_parse.parser.MainTheme.get_infos}




>     def get_infos(
>         self
>     )


Return 1 info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.MainTheme.get_warnings}




>     def get_warnings(
>         self
>     )


Return Main Theme warnings

    
### Class `Media` {#wpscan_out_parse.parser.Media}




>     class Media(
>         url,
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.Media.get_alerts}




>     def get_alerts(
>         self
>     )


Return empty list

    
##### Method `get_infos` {#wpscan_out_parse.parser.Media.get_infos}




>     def get_infos(
>         self
>     )


Return 1 Media info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Media.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `NotFullyConfigured` {#wpscan_out_parse.parser.NotFullyConfigured}




>     class NotFullyConfigured(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.NotFullyConfigured.get_alerts}




>     def get_alerts(
>         self
>     )


Return 1 alert

    
##### Method `get_infos` {#wpscan_out_parse.parser.NotFullyConfigured.get_infos}




>     def get_infos(
>         self
>     )


Return empty list

    
##### Method `get_name` {#wpscan_out_parse.parser.NotFullyConfigured.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.NotFullyConfigured.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `PasswordAttack` {#wpscan_out_parse.parser.PasswordAttack}




>     class PasswordAttack(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.PasswordAttack.get_alerts}




>     def get_alerts(
>         self
>     )


Return Password Attack Valid Combinations Found alerts

    
##### Method `get_infos` {#wpscan_out_parse.parser.PasswordAttack.get_infos}




>     def get_infos(
>         self
>     )


Return empty list

    
##### Method `get_name` {#wpscan_out_parse.parser.PasswordAttack.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.PasswordAttack.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `Plugin` {#wpscan_out_parse.parser.Plugin}




>     class Plugin(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_infos` {#wpscan_out_parse.parser.Plugin.get_infos}




>     def get_infos(
>         self
>     )


Return 1 or 0 info if pluging trigerred warning

    
##### Method `get_name` {#wpscan_out_parse.parser.Plugin.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Plugin.get_warnings}




>     def get_warnings(
>         self
>     )


Return plugin warnings

    
### Class `ScanFinished` {#wpscan_out_parse.parser.ScanFinished}




>     class ScanFinished(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.ScanFinished.get_alerts}




>     def get_alerts(
>         self
>     )


Return empty list

    
##### Method `get_infos` {#wpscan_out_parse.parser.ScanFinished.get_infos}




>     def get_infos(
>         self
>     )


Return 1 Scan Finished info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.ScanFinished.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `ScanStarted` {#wpscan_out_parse.parser.ScanStarted}




>     class ScanStarted(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.ScanStarted.get_alerts}




>     def get_alerts(
>         self
>     )


Return empty list

    
##### Method `get_infos` {#wpscan_out_parse.parser.ScanStarted.get_infos}




>     def get_infos(
>         self
>     )


Return 1 Scan Scanned info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.ScanStarted.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `Theme` {#wpscan_out_parse.parser.Theme}




>     class Theme(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)


    
#### Descendants

* [wpscan_out_parse.parser.MainTheme](#wpscan_out_parse.parser.MainTheme)





    
#### Methods


    
##### Method `get_name` {#wpscan_out_parse.parser.Theme.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Theme.get_warnings}




>     def get_warnings(
>         self
>     )


Return theme warnings

    
### Class `Timthumb` {#wpscan_out_parse.parser.Timthumb}




>     class Timthumb(
>         url,
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.Timthumb.get_alerts}




>     def get_alerts(
>         self
>     )


Return timthumb vulnerabilities

    
##### Method `get_infos` {#wpscan_out_parse.parser.Timthumb.get_infos}




>     def get_infos(
>         self
>     )


Return 1 info

    
##### Method `get_name` {#wpscan_out_parse.parser.Timthumb.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_version` {#wpscan_out_parse.parser.Timthumb.get_version}




>     def get_version(
>         self
>     )


Return the version number (as string)

    
##### Method `get_version_status` {#wpscan_out_parse.parser.Timthumb.get_version_status}




>     def get_version_status(
>         self
>     )


Return a string in : "Outdated", "Latest", "NA", "Unknown"

    
##### Method `get_vulnerabilities_string` {#wpscan_out_parse.parser.Timthumb.get_vulnerabilities_string}




>     def get_vulnerabilities_string(
>         self
>     )


Return the number of vulnerabilities,   (as string)

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Timthumb.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `User` {#wpscan_out_parse.parser.User}




>     class User(
>         username,
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb>
And <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.User.get_alerts}




>     def get_alerts(
>         self
>     )


Return 0 or 1 alert. Alert if password found. Used by PasswordAttack component

    
##### Method `get_infos` {#wpscan_out_parse.parser.User.get_infos}




>     def get_infos(
>         self
>     )


Return 1 info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.User.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `VulnAPI` {#wpscan_out_parse.parser.VulnAPI}




>     class VulnAPI(
>         data,
>         *args,
>         **kwargs
>     )


Base abstract class for all WPScan JSON and CLI components

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.VulnAPI.get_alerts}




>     def get_alerts(
>         self
>     )


Return empty list

    
##### Method `get_infos` {#wpscan_out_parse.parser.VulnAPI.get_infos}




>     def get_infos(
>         self
>     )


Return 1 WPVulnDB info

    
##### Method `get_warnings` {#wpscan_out_parse.parser.VulnAPI.get_warnings}




>     def get_warnings(
>         self
>     )


Return 0 or 1 warning. VulnAPI error No WPVulnDB API Token given or HTTP errors

    
### Class `Vulnerability` {#wpscan_out_parse.parser.Vulnerability}




>     class Vulnerability(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.Vulnerability.get_alerts}




>     def get_alerts(
>         self
>     )


Return 1 alert. First line of alert string contain the vulnerability title. Process CVE, WPVulnDB, ExploitDB and Metasploit references to add links

    
##### Method `get_infos` {#wpscan_out_parse.parser.Vulnerability.get_infos}




>     def get_infos(
>         self
>     )


Return empty list

    
##### Method `get_warnings` {#wpscan_out_parse.parser.Vulnerability.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `WPItem` {#wpscan_out_parse.parser.WPItem}




>     class WPItem(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)


    
#### Descendants

* [wpscan_out_parse.parser.Plugin](#wpscan_out_parse.parser.Plugin)
* [wpscan_out_parse.parser.Theme](#wpscan_out_parse.parser.Theme)





    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.WPItem.get_alerts}




>     def get_alerts(
>         self
>     )


Return list of know plugin or theme vulnerability. Empty list is returned if plugin version is unrecognized

    
##### Method `get_infos` {#wpscan_out_parse.parser.WPItem.get_infos}




>     def get_infos(
>         self
>     )


Return 0 or 1 info, no info if WPItem triggered warning, use get_warnings()

    
##### Method `get_version` {#wpscan_out_parse.parser.WPItem.get_version}




>     def get_version(
>         self
>     )


Return the version number (as string)

    
##### Method `get_version_status` {#wpscan_out_parse.parser.WPItem.get_version_status}




>     def get_version_status(
>         self
>     )


Return a string in : "Outdated", "Latest", "NA", "Unknown"

    
##### Method `get_vulnerabilities_string` {#wpscan_out_parse.parser.WPItem.get_vulnerabilities_string}




>     def get_vulnerabilities_string(
>         self
>     )


Return the number of vulnerabilities,   (as string)

    
##### Method `get_warnings` {#wpscan_out_parse.parser.WPItem.get_warnings}




>     def get_warnings(
>         self
>     )


Return plugin or theme warnings, if oudated plugin, directory listing, accessible error log and 
for all know vulnerabilities if plugin version could not be recognized.
Adds a special text saying the version is unrecognized if that's the case

    
### Class `WPItemVersion` {#wpscan_out_parse.parser.WPItemVersion}




>     class WPItemVersion(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

Themes, plugins and timthumbs Version. From:
<https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb>
<https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb>
<https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.WPItemVersion.get_alerts}




>     def get_alerts(
>         self
>     )


Return any item version vulnerabilities

    
##### Method `get_infos` {#wpscan_out_parse.parser.WPItemVersion.get_infos}




>     def get_infos(
>         self
>     )


Return 0 or 1 info. No infos if version could not be recognized

    
##### Method `get_version` {#wpscan_out_parse.parser.WPItemVersion.get_version}




>     def get_version(
>         self
>     )




    
##### Method `get_warnings` {#wpscan_out_parse.parser.WPItemVersion.get_warnings}




>     def get_warnings(
>         self
>     )


Return empty list

    
### Class `WordPressVersion` {#wpscan_out_parse.parser.WordPressVersion}




>     class WordPressVersion(
>         data,
>         *args,
>         **kwargs
>     )


Generic WPScan finding

From <https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb>


    
#### Ancestors (in MRO)

* [wpscan_out_parse.parser._Finding](#wpscan_out_parse.parser._Finding)
* [wpscan_out_parse.parser._Component](#wpscan_out_parse.parser._Component)
* [wpscan_out_parse.parser._CoreFinding](#wpscan_out_parse.parser._CoreFinding)
* [abc.ABC](#abc.ABC)






    
#### Methods


    
##### Method `get_alerts` {#wpscan_out_parse.parser.WordPressVersion.get_alerts}




>     def get_alerts(
>         self
>     )


Return Wordpress Version vulnerabilities

    
##### Method `get_infos` {#wpscan_out_parse.parser.WordPressVersion.get_infos}




>     def get_infos(
>         self
>     )


Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use get_warnings()

    
##### Method `get_name` {#wpscan_out_parse.parser.WordPressVersion.get_name}




>     def get_name(
>         self
>     )


Return the name of the finding.

    
##### Method `get_version` {#wpscan_out_parse.parser.WordPressVersion.get_version}




>     def get_version(
>         self
>     )


Return the version string or 'Unknown'

    
##### Method `get_version_status` {#wpscan_out_parse.parser.WordPressVersion.get_version_status}




>     def get_version_status(
>         self
>     )


Return a string in : "Outdated", "Latest", "NA", "Unknown"

    
##### Method `get_vulnerabilities_string` {#wpscan_out_parse.parser.WordPressVersion.get_vulnerabilities_string}




>     def get_vulnerabilities_string(
>         self
>     )


Return the number of vulnerabilities,   (as string)

    
##### Method `get_warnings` {#wpscan_out_parse.parser.WordPressVersion.get_warnings}




>     def get_warnings(
>         self
>     )


Return 0 or 1 warning


-----
Generated by *pdoc* 0.8.4 (<https://pdoc3.github.io>).
