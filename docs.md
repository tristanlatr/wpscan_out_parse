Module `wpscan_out_parse`
=========================

WPScan Output Parser Python library documentation.

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

Parse any WPScan output file.

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

-   [wpscan\_out\_parse.parser.base.\_Parser](#wpscan_out_parse.parser.base._Parser)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
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

Parse the ( messages, warnings, alerts ) from WPScan CLI output string.
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

And the following properties are accessible: version, main\_theme,
plugins, themes, interesting\_findings, password\_attack,
not\_fully\_configured, timthumbs, db\_exports, users, medias,
config\_backups, vuln\_api, banner, scan\_started, scan\_finished

#### Ancestors (in MRO)

-   [wpscan\_out\_parse.parser.base.\_Parser](#wpscan_out_parse.parser.base._Parser)
-   [wpscan\_out\_parse.parser.base.\_Component](#wpscan_out_parse.parser.base._Component)
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

------------------------------------------------------------------------

Generated by *pdoc* 0.8.4
(<a href="https://pdoc3.github.io" class="uri">https://pdoc3.github.io</a>).
