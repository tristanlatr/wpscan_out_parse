Module `wpscan_out_parse`
=========================

WPScan Output Parser Python library documentation.

Functions
---------

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

### Function `parse_results_from_file`

>     def parse_results_from_file(
>         wpscan_output_file,
>         false_positives_strings=None,
>         show_all_details=False
>     )

Parse any WPScan output file.

-   wpscan\_output\_file: Path to WPScan output file
-   false\_positives\_strings: List of false positive strings.
-   show\_all\_details: Boolean, enable to show all wpscan infos (found
    by, confidence, etc). Only with JSON output.

Return the results as dict object

### Function `format_results`

>     def format_results(
>         results,
>         format,
>         warnings=True,
>         infos=True,
>         nocolor=False
>     )

Format the results dict into a “html”, “cli” or “json” string.

-   results: resutlts dict objject.
-   format: in `"html"`, `"cli"` or `"json"`

Classes
-------

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

Once instanciated, the following properties are accessible:

-   <code>version</code>
-   <code>main\_theme</code>
-   <code>plugins</code> (list)
-   <code>themes</code> (list)
-   <code>interesting\_findings</code> (list)
-   <code>timthumbs</code> (list)
-   <code>db\_exports</code> (list)
-   <code>users</code> (list)
-   <code>medias</code> (list)
-   <code>config\_backups</code> (list)
-   <code>password\_attack</code>
-   <code>not\_fully\_configured</code>
-   <code>vuln\_api</code>
-   <code>banner</code>
-   <code>scan\_started</code>
-   <code>scan\_finished</code>

All objects implements <code>get\_alerts()</code>,
<code>get\_warnings()</code> and <code>get\_infos()</code>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.base.\_Parser](#wpscan_out_parse.parser.base._Parser)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Get all infos from all components and add false positives as infos with
“\[False positive\]” prefix

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Get all warnings from all components and igore false positives and
automatically remove special warning if all vuln are ignored

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Get all alerts from all components and igore false positives

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

##### Method `get_core_findings`

>     def get_core_findings(
>         self
>     )

Get only core findings. Core findings appears in the table summary.

##### Method `get_summary_list`

>     def get_summary_list(
>         self
>     )

Return a list of dict with all plugins, vuls, and statuses.

##### Method `get_error`

>     def get_error(
>         self
>     )

Return any error or None if no errors

### Class `WPScanCliParser`

>     class WPScanCliParser(
>         wpscan_output,
>         false_positives_strings=None
>     )

Main interface to parse WPScan CLI output.

-   wpscan\_output: WPScan output as string.
-   false\_positives\_strings: List of false positive strings.

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.base.\_Parser](#wpscan_out_parse.parser.base._Parser)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return all the parsed infos

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return all the parsed warnings

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return all the parsed alerts

##### Method `parse_cli`

>     def parse_cli(
>         self,
>         wpscan_output
>     )

Parse the ( messages, warnings, alerts ) from WPScan CLI output string.
Return results as tuple( messages, warnings, alerts ).

##### Method `get_error`

>     def get_error(
>         self
>     )

Return any error or None if no errors

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

Module `wpscan_out_parse.parser.results`
========================================

Module `wpscan_out_parse.parser.base`
=====================================

Module `wpscan_out_parse.parser.components`
===========================================

Classes
-------

### Class `WordPressVersion`

>     class WordPressVersion(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding: Shows on the summary table.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/wp_version/version.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info, no infos if WordPressVersion triggedred warning, use
get\_warnings()

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return 0 or 1 warning

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return Wordpress Version vulnerabilities

##### Method `get_version`

>     def get_version(
>         self
>     )

Return the version string or ‘Unknown’

##### Method `get_version_status`

>     def get_version_status(
>         self
>     )

Return a string in : “Outdated”, “Latest”, “Unknown” or "" if not
applicable.

##### Method `get_vulnerabilities_string`

>     def get_vulnerabilities_string(
>         self
>     )

Return the number of vulnerabilities (as string) with indications if
need be.

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

### Class `Plugin`

>     class Plugin(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding: Shows on the summary table.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/plugins.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.wp\_item.WPItem](#wpscan_out_parse.parser.components.wp_item.WPItem)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 1 or 0 info if pluging trigerred warning

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return plugin warnings

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

### Class `Theme`

>     class Theme(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding: Shows on the summary table.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/theme.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.wp\_item.WPItem](#wpscan_out_parse.parser.components.wp_item.WPItem)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Descendants

-   [wpscan\_out\_parse.parser.components.main\_theme.MainTheme](#wpscan_out_parse.parser.components.main_theme.MainTheme)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info, no info if WPItem triggered warning, use
get\_warnings()

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return theme warnings

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

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

-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Class variables

##### Variable `INTERESTING_FINDING_WARNING_STRINGS`

##### Variable `INTERESTING_FINDING_ALERT_STRINGS`

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return list of alerts if finding match ALERT string

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

-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
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

Core WPScan finding that do not have version identifier.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/config_backups.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.finding.\_CoreFindingNoVersion](#wpscan_out_parse.parser.components.finding._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 Config Backup alert

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

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

### Class `DBExport`

>     class DBExport(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding that do not have version identifier.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/db_exports.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.finding.\_CoreFindingNoVersion](#wpscan_out_parse.parser.components.finding._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 DBExport alert

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

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

### Class `MainTheme`

>     class MainTheme(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding: Shows on the summary table.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/main_theme/theme.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.theme.Theme](#wpscan_out_parse.parser.components.theme.Theme)
-   [wpscan\_out\_parse.parser.components.wp\_item.WPItem](#wpscan_out_parse.parser.components.wp_item.WPItem)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
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

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

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

-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

### Class `NotFullyConfigured`

>     class NotFullyConfigured(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding that do not have version identifier.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/core/not_fully_configured.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.finding.\_CoreFindingNoVersion](#wpscan_out_parse.parser.components.finding._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 1 alert

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

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

### Class `PasswordAttack`

>     class PasswordAttack(
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding that do not have version identifier.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/password_attack/users.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.finding.\_CoreFindingNoVersion](#wpscan_out_parse.parser.components.finding._CoreFindingNoVersion)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return Password Attack Valid Combinations Found alerts

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Return empty list

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

-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
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

-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

### Class `Timthumb`

>     class Timthumb(
>         url,
>         data,
>         *args,
>         **kwargs
>     )

Core WPScan finding: Shows on the summary table.

From
<a href="https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb" class="uri">https://github.com/wpscanteam/wpscan/blob/master/app/views/json/enumeration/timthumbs.erb</a>

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.components.wp\_item.WPItem](#wpscan_out_parse.parser.components.wp_item.WPItem)
-   [wpscan\_out\_parse.parser.components.finding.\_CoreFinding](#wpscan_out_parse.parser.components.finding._CoreFinding)
-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

##### Method `get_infos`

>     def get_infos(
>         self
>     )

Return 0 or 1 info, no info if Timthumb triggered warning, use
get\_warnings()

##### Method `get_warnings`

>     def get_warnings(
>         self
>     )

Returns warnings

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return timthumb vulnerabilities

##### Method `get_name`

>     def get_name(
>         self
>     )

Return the name of the finding.

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

-   [wpscan\_out\_parse.parser.components.finding.\_Finding](#wpscan_out_parse.parser.components.finding._Finding)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
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

Return empty list

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return 0 or 1 alert. Alert if password found. Used by PasswordAttack
component

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

-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
-   [abc.ABC](#abc.ABC)

#### Methods

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

##### Method `get_alerts`

>     def get_alerts(
>         self
>     )

Return empty list

Module `wpscan_out_parse.formatter`
===================================

Functions
---------

### Function `format_results`

>     def format_results(
>         results,
>         format,
>         warnings=True,
>         infos=True,
>         nocolor=False
>     )

Format the results dict into a “html”, “cli” or “json” string.

-   results: resutlts dict objject.
-   format: in `"html"`, `"cli"` or `"json"`

### Function `build_message`

>     def build_message(
>         results,
>         warnings=True,
>         infos=True,
>         format='cli',
>         nocolor=False
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

### Function `get_table_cell_color`

>     def get_table_cell_color(
>         col,
>         val,
>         ansi=False
>     )

### Function `format_summary_ascii_table`

>     def format_summary_ascii_table(
>         table,
>         line,
>         nocolor=False
>     )

Return a nice string table Author: Thierry Husson - Use it as you want
but don’t blame me.

### Function `format_summary_html`

>     def format_summary_html(
>         table,
>         line,
>         nocolor
>     )

### Function `replace`

>     def replace(
>         text,
>         conditions
>     )

Multiple replacements helper method. Stolen on the web

------------------------------------------------------------------------

Generated by *pdoc* 0.9.1
(<a href="https://pdoc3.github.io" class="uri">https://pdoc3.github.io</a>).
