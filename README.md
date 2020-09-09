# WPScan Output Parse

**`wpscan_out_parse` is a Python parser for WPScan output files** (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.  

<a href="https://github.com/tristanlatr/wpscan_out_parse/actions" target="_blank"><img src="https://github.com/tristanlatr/wpscan_out_parse/workflows/test/badge.svg"></a>
<a href="https://codecov.io/gh/tristanlatr/wpscan_out_parse" target="_blank"><img src="https://codecov.io/gh/tristanlatr/wpscan_out_parse/branch/master/graph/badge.svg"></a>
<a href="https://pypi.org/project/wpscan-out-parse/" target="_blank"><img src="https://badge.fury.io/py/wpscan-out-parse.svg"></a>

### Features
- Support WPScan JSON and CLI output files
- Display results to stdout in CLI, JSON or HTML output format
- Generate a summary table of your wordpress component containing version and vulnerabilities  
- Divide the results in "Alerts", "Warnings" and "Informations"
- Additionnal alerts depending of finding type (SQL dump, etc.)  
- Signal result via exit code
- Ignore messages based on false positives strings 
- Simple Python library usage 
- Colorized output by default

Design of summary table is largely inspired by [wpscan-analyze](https://github.com/lukaspustina/wpscan-analyze) (Rust code).  

### Install
```
python3 -m pip install wpscan-out-parse
```
No dependencies

## How to use

### As a CLI tool
Run WPScan
```bash
wpscan --url https://mysite.com --output file.json --format json --api-token YOUR_API_TOKEN
```

Run **`wpscan_out_parse`**  
```bash
python3 -m wpscan_out_parse file.json
```
And process output and/or exit code

#### Exit codes
- 5 -> ALERT: Your WordPress site is vulnerable
- 6 -> WARNING: You WordPress site is oudated or potentially vulnerable
- 4 -> ERROR: WPScan failed
- 1 -> ERROR: Parser error
- 0 -> All OK

#### Exemples

Display results in CLI format
```bash
% python3 -m wpscan_out_parse ./test/output_files/wordpress_many_vuln.json --no_warn --no_color

Vulnerabilities have been detected by WPScan.

        Summary
        -------

Component                    | Version | Version State | Vulnerabilities | Status 
---------------------------- | ------- | ------------- | --------------- | -------
WordPress 5.2.2 (2019-06-18) | 5.2.2   | Latest        | 0               | Ok     
Main Theme: customizr        | 4.1.42  | Latest        | 1               | Alert  
Plugin: youtube-embed-plus   | Unknown | N/A           | 2 (potential)   | Warning

WPScan result summary: alerts=1, warnings=5, infos=9, error=0

        Alerts
        ------

Vulnerability: YouTube Embed <= 13.8.1 - Cross-Site Request Forgery (CSRF)
Fixed in: 11.8.2
References: 
- Url: https://security.dxw.com/advisories/csrf-in-youtube-plugin/
- Url: http://seclists.org/fulldisclosure/2017/Jul/64
- WPVulnDB: https://wpvulndb.com/vulnerabilities/8873
```

Display results in HTML format
```bash
% python3 -m wpscan_out_parse ./test/output_files/potential_vulns.json --format html > html_output.html
```

![WPWatcher Report](https://github.com/tristanlatr/wpscan_out_parse/raw/master/html_output.png "HTML Output")

### As a Python library

The python module exposes helper methods and Parser objects to parse WPScan results as your convevnience.  

#### Exemples

Using helper method `parse_results_from_file()`.  Return all results as a simple dictionnary.  

```python
import pprint
from wpscan_out_parse import parse_results_from_file

results = parse_results_from_file('./test/output_files/wordpress_many_vuln.json')
pprint.pprint(results)
```

Using `WPScanJsonParser` object.  

```python
import json
import pprint
from wpscan_out_parse import WPScanJsonParser

with open('./test/output_files/wordpress_one_vuln.json', 'r') as wpscan_out:
    parser = WPScanJsonParser(json.load(wpscan_out))
    pprint.pprint(parser.get_warnings())
```
Once `WPScanJsonParser` instanciated, the following properties are accessible:  

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

See [docs.md](https://github.com/tristanlatr/wpscan_out_parse/blob/master/docs.md) for more technicals details on Python objects and library usage.  

### Additionnal alerts strings
Some additionnal warnings and alerts are raised when detecting the following strings in your output file.  

Alerts 
```python
"SQL Dump found",
"Full Path Disclosure found",
"www.owasp.org/index.php/Full_Path_Disclosure",
"codex.wordpress.org/Resetting_Your_Password#Using_the_Emergency_Password_Reset_Script",
"www.exploit-db.com/ghdb/3981/",
"A backup directory has been found",
"github.com/wpscanteam/wpscan/issues/422",
"ThemeMakers migration file found",
"packetstormsecurity.com/files/131957",
"Search Replace DB script found",
"interconnectit.com/products/search-and-replace-for-wordpress-databases/"
```

Warnings
```python
"Upload directory has listing enabled",
"Registration is enabled",
"Debug Log found",
"codex.wordpress.org/Debugging_in_WordPress",
"Fantastico list found",
"www.acunetix.com/vulnerabilities/fantastico-fileslist/"
```


### Full help
```bash
% python3 -m wpscan_out_parse -h
usage: python3 -m wpscan_out_parse [Options] <File path>

wpscan_out_parse is a Python parser for WPScan output files (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.

positional arguments:
  <File path>           WPScan output file to parse.

optional arguments:
  -h, --help            show this help message and exit
  --format <Format>     output format, choices are: "cli", "html", "json"
  --summary             display ony the summary of issues per component.
  --inline              display only one line like: "WPScan result summary:
                        alerts={}, warnings={}, infos={}, error={}".
  --no_warnings         do not display warnings, only summary and alerts.
                        Implies --no_infos.
  --no_infos            do not display informations and findinds.
  --no_summary          do not display the summary of issues.
  --show_all            show all findings details (found by, confidence,
                        confirmed by).
  --false_positive String [String ...]
                        consider all matching messages as infos and add
                        "[False positive]" prefix.
  --no_color            do not colorize output.
  --version             print wpscan_out_parse version and exit.

  ```
