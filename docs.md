Module `wpscan_out_parse`
=========================

WPScan Output Parser technical documentation.

Sub-modules
-----------

-   [wpscan\_out\_parse.formatter](#wpscan_out_parse.formatter)
-   [wpscan\_out\_parse.parser](#wpscan_out_parse.parser)

Functions
---------

### Function `format_results`

>     def format_results(
>         results,
>         format
>     )

Format the results dict into a “html”, “cli” or “json” string.

-   results: resutlts dict objject  
-   format: in “html”, “cli” or “json”

### Function `parse_results_from_file`

>     def parse_results_from_file(
>         wpscan_output_file,
>         false_positives_strings=None,
>         show_all_details=False
>     )

Prse any WPScan output file.

-   wpscan\_output\_file: Path to WPScan output file
-   false\_positives\_strings: List of false positive strings.  
-   show\_all\_details: Boolean, enable to show all wpscan infos (found
    by, confidence, etc). Only with JSON output.

Return the results as dict object

### Function `parse_results_from_string`

>     def parse_results_from_string(
>         wpscan_output_string,
>         false_positives_strings=None,
>         show_all_details=False
>     )

Parse any WPScan output string.

-   wpscan\_output\_string: WPScan output as string
-   false\_positives\_strings: List of false positive strings.  
-   show\_all\_details: Boolean, enable to show all wpscan infos (found
    by, confidence, etc). Only with JSON output.

Return the results as dict object

Classes
-------

### Class `WPScanCliParser`

>     class WPScanCliParser(
>         wpscan_output,
>         false_positives_strings=None
>     )

Main interface to parse WPScan CLI output.

-   wpscan\_output: WPScan output as string.  
-   false\_positives\_strings: List of false positive strings.

Once instanciated, wpscan\_output is parsed and the following methods
are accessible: get\_infos(), get\_warnings(), get\_alerts()

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Parser](#wpscan_out_parse.parser._Parser)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return all the parsed alerts

##### Method `get_error`

>     def get_error(
>         self
>     )

Return any error or None if no errors

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return all the parsed infos

##### Method `get_results`

>     def get_results(
>         self
>     )

Returns a dictionnary structure like:

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

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return all the parsed warnings

##### Method `parse_cli`

>     def parse_cli(
>         self,
>         wpscan_output
>     )

Parse the ( messages, warnings, alerts ) from WPScan CLI output
string.  
Return results as tuple( messages, warnings, alerts ).

### Class `WPScanJsonParser`

>     class WPScanJsonParser(
>         data,
>         false_positives_strings=None,
>         show_all_details=False
>     )

Main interface to parse WPScan JSON data

-   data: The JSON structure of the WPScan output.  
-   false\_positives\_strings: List of false positive strings.  
-   show\_all\_details: Boolean, enable to show all wpscan infos (found
    by, confidence, etc).

Once instanciated, the following methods are accessible: get\_infos(),
get\_warnings(), get\_alerts()

And the following properties are accessible:  
version, main\_theme, plugins, themes, interesting\_findings,
password\_attack, not\_fully\_configured, timthumbs, db\_exports, users,
medias, config\_backups, vuln\_api, banner, scan\_started,
scan\_finished

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Parser](#wpscan_out_parse.parser._Parser)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Get all alerts from all components and igore false positives

##### Method `get_core_findings`

>     def get_core_findings(
>         self
>     )

Get only core findings. Core findings appears in the table summary.

##### Method `get_error`

>     def get_error(
>         self
>     )

Return any error or None if no errors

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Get all infos from all components and add false positives as infos with
“\[False positive\]” prefix

##### Method `get_results`

>     def get_results(
>         self
>     )

Returns a dictionnary structure like:

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

##### Method `get_summary_list`

>     def get_summary_list(
>         self
>     )

Return a list of dict with all plugins, vuls, and statuses.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Get all warnings from all components and igore false positives and
automatically remove special warning if all vuln are ignored

Module `wpscan_out_parse.formatter`
===================================

Functions
---------

### Function `build_message`

>     def build_message(
>         results,
>         warnings=True,
>         infos=True,
>         format='cli'
>     )

Build mail message text base on report and warnngs and info switch

### Function `format_issues`

>     def format_issues(
>         title,
>         issues,
>         format='cli',
>         apply_br_tab_replace_on_issues=True
>     )

Format one block of issues to text with the title

### Function `format_summary_ascii_table`

>     def format_summary_ascii_table(
>         table,
>         line
>     )

Return a nice string table Author: Thierry Husson - Use it as you want
but don’t blame me.

### Function `format_summary_html`

>     def format_summary_html(
>         table,
>         line
>     )

### Function `replace`

>     def replace(
>         text,
>         conditions
>     )

Multiple replacements helper method. Stolen on the web

Module `wpscan_out_parse.parser`
================================

Classes
-------

### Class `Banner`

>     class Banner(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/banner.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return the component informations as a list of strings.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `ConfigBackup`

>     class ConfigBackup(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 Config Backup alert

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return empty list

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `DBExport`

>     class DBExport(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 DBExport alert

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return empty list

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `InterestingFinding`

>     class InterestingFinding(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb" class="uri">https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/interesting_findings/findings.erb</a>  
Warnings and Alerts strings are from
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/models/interesting_finding.rb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/models/interesting_finding.rb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Class variables

##### Variable `INTERESTING_FINDING_ALERT_STRINGS`

##### Variable `INTERESTING_FINDING_WARNING_STRINGS`

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return list of alerts if finding match ALERT string

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 info or 0 if finding is a warning or an alert

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return list of warnings if finding match warning string

### Class `MainTheme`

>     class MainTheme(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.Theme](#wpscan_out_parse.parser.Theme)
-   [wpscan\_out\_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return Main Theme warnings

### Class `Media`

>     class Media(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/medias.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 Media info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `NotFullyConfigured`

>     class NotFullyConfigured(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 alert

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return empty list

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `PasswordAttack`

>     class PasswordAttack(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFindingNoVersion](#wpscan_out_parse.parser._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return Password Attack Valid Combinations Found alerts

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return empty list

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `Plugin`

>     class Plugin(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 or 0 info if pluging trigerred warning

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return plugin warnings

### Class `ScanFinished`

>     class ScanFinished(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb" class="uri">https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/finished.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 Scan Finished info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `ScanStarted`

>     class ScanStarted(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb" class="uri">https://github.com/wpscanteam/CMSScanner/blob/master/app/views/json/core/started.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 Scan Scanned info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `Theme`

>     class Theme(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.WPItem](#wpscan_out_parse.parser.WPItem)
-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Descendants

-   [wpscan\_out\_parse.parser.MainTheme](#wpscan_out_parse.parser.MainTheme)

#### Methods

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return theme warnings

### Class `Timthumb`

>     class Timthumb(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return timthumb vulnerabilities

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 info

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_version`

>     def get_version(
>         self
>     )

Return the version number (as string)

##### Method `get_version_status`

>     def get_version_status(
>         self
>     )

Return a string in : “Outdated”, “Latest”, “NA”, “Unknown”

##### Method `get_vulnerabilities_string`

>     def get_vulnerabilities_string(
>         self
>     )

Return the number of vulnerabilities, (as string)

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `User`

>     class User(
>         username,
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/users.erb</a>
And
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 0 or 1 alert. Alert if password found. Used by PasswordAttack
component

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `VulnAPI`

>     class VulnAPI(
>         data,
>         *args,
>         **kwargs
>     )

Base abstract class for all WPScan JSON and CLI components

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/vuln_api/status.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 WPVulnDB info

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return 0 or 1 warning. VulnAPI error No WPVulnDB API Token given or HTTP
errors

### Class `Vulnerability`

>     class Vulnerability(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/finding.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 alert. First line of alert string contain the vulnerability
title. Process CVE, WPVulnDB, ExploitDB and Metasploit references to add
links

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return empty list

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `WPItem`

>     class WPItem(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_item.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Descendants

-   [wpscan\_out\_parse.parser.Plugin](#wpscan_out_parse.parser.Plugin)
-   [wpscan\_out\_parse.parser.Theme](#wpscan_out_parse.parser.Theme)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return list of know plugin or theme vulnerability. Empty list is
returned if plugin version is unrecognized

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info, no info if WPItem triggered warning, use
get\_warnings()

##### Method `get_version`

>     def get_version(
>         self
>     )

Return the version number (as string)

##### Method `get_version_status`

>     def get_version_status(
>         self
>     )

Return a string in : “Outdated”, “Latest”, “NA”, “Unknown”

##### Method `get_vulnerabilities_string`

>     def get_vulnerabilities_string(
>         self
>     )

Return the number of vulnerabilities, (as string)

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return plugin or theme warnings, if oudated plugin, directory listing,
accessible error log and for all know vulnerabilities if plugin version
could not be recognized. Adds a special text saying the version is
unrecognized if that’s the case

### Class `WPItemVersion`

>     class WPItemVersion(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

Themes, plugins and timthumbs Version. From:
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb</a>
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb</a>
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return any item version vulnerabilities

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info. No infos if version could not be recognized

##### Method `get_version`

>     def get_version(
>         self
>     )

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

### Class `WordPressVersion`

>     class WordPressVersion(
>         data,
>         *args,
>         **kwargs
>     )

Generic WPScan finding

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.\_Finding](#wpscan_out_parse.parser._Finding)
-   [wpscan\_out\_parse.parser.\_Component](#wpscan_out_parse.parser._Component)
-   [wpscan\_out\_parse.parser.\_CoreFinding](#wpscan_out_parse.parser._CoreFinding)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return Wordpress Version vulnerabilities

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use
get\_warnings()

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

##### Method `get_version`

>     def get_version(
>         self
>     )

Return the version string or ‘Unknown’

##### Method `get_version_status`

>     def get_version_status(
>         self
>     )

Return a string in : “Outdated”, “Latest”, “NA”, “Unknown”

##### Method `get_vulnerabilities_string`

>     def get_vulnerabilities_string(
>         self
>     )

Return the number of vulnerabilities, (as string)

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return 0 or 1 warning

------------------------------------------------------------------------

Generated by *pdoc* 0.8.4
(<a href="https://pdoc3.github.io" class="uri">https://pdoc3.github.io</a>).
