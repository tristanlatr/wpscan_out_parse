# WPScan Output Parse

**`wpscan_out_parse` is a Python parser for WPScan output files** (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.

<a href="https://github.com/tristanlatr/wpscan_out_parse/actions" target="_blank"><img src="https://github.com/tristanlatr/wpscan_out_parse/workflows/test/badge.svg"></a>
<a href="https://codecov.io/gh/tristanlatr/wpscan_out_parse" target="_blank"><img src="https://codecov.io/gh/tristanlatr/wpscan_out_parse/branch/master/graph/badge.svg"></a>
<a href="https://pypi.org/project/wpscan_out_parse/" target="_blank"><img src="https://badge.fury.io/py/wpscan_out_parse.svg"></a>

### Features
- Support WPScan JSON and CLI output files
- Return results in CLI, JSON and HTML output format
- Divide the results in "Alerts", "Warnings" and "Informations"
- Additionnal alerts depending of finding type (SQL dump, etc.)  
- Signal result via exit code
- Ignore messages based on false positives strings 
- Simple Python library usage

### Install
```
python3 -m pip install wpscan_out_parse
```
No dependencies

## How to use

### As a CLI tool
Run `wpscan [options] --output yourfile`  
```bash
wpscan --url https://mysite.com --output file.json --format json --api-token YOUR_API_TOKEN
```

Run `wpscan_out_parse [options] yourfile`  
```bash
python3 -m wpscan_out_parse --alerts file.json
```
And process output and/or exit code

#### Exit codes
- 5 -> ALERT: Your WordPress site is vulnerable
- 6 -> WARNING: You WordPress site is oudated or potentially vulnerable
- 4 -> ERROR: WPScan failed
- 1 -> ERROR: Parser error
- 0 -> All OK

### As a Python library
```python
import wpscan_out_parse
results=wpscan_out_parse.parse_results_from_file('wpscan_output_file.json')
print(results)
```

### Exemples

```bash
% python3 -m wpscan_out_parse ./test/output_files/wordpress_many_vuln.json --no_warn

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

#### Display results in HTML
```html
% python3 -m wpscan_out_parse ./test/output_files/wordpress_many_vuln.json --no_warn --format html
<div><br/>Vulnerabilities have been detected by WPScan.<br/><br/>&nbsp;&nbsp;&nbsp;&nbsp;Summary<br/>&nbsp;&nbsp;&nbsp;&nbsp;-------<br/><br/><table><tr><th>Component</th><th>Version</th><th>Version State</th><th>Vulnerabilities</th><th>Status</th></tr></table><br/>WPScan result summary: alerts=1, warnings=5, infos=9, error=0<br/><br/>&nbsp;&nbsp;&nbsp;&nbsp;Alerts<br/>&nbsp;&nbsp;&nbsp;&nbsp;------<br/><br/>Vulnerability: YouTube Embed <= 13.8.1 - Cross-Site Request Forgery (CSRF)<br/>Fixed in: 11.8.2<br/>References: <br/>- Url: https://security.dxw.com/advisories/csrf-in-youtube-plugin/<br/>- Url: http://seclists.org/fulldisclosure/2017/Jul/64<br/>- WPVulnDB: https://wpvulndb.com/vulnerabilities/8873<br/></div>
```

#### Display results in JSON
```bash
% python3 -m wpscan_out_parse ./test/output_files/wordpress_many_vuln.json --no_warn --format json 
{
    "infos": null,
    "warnings": null,
    "alerts": [
        "Vulnerability: YouTube Embed <= 13.8.1 - Cross-Site Request Forgery (CSRF)\nFixed in: 11.8.2\nReferences: \n- Url: https://security.dxw.com/advisories/csrf-in-youtube-plugin/\n- Url: http://seclists.org/fulldisclosure/2017/Jul/64\n- WPVulnDB: https://wpvulndb.com/vulnerabilities/8873"
    ],
    "summary": {
        "table": [
            {
                "Component": "WordPress 5.2.2 (2019-06-18)",
                "Version": "5.2.2",
                "Version State": "Latest",
                "Vulnerabilities": "0",
                "Status": "Ok"
            },
            {
                "Component": "Main Theme: customizr",
                "Version": "4.1.42",
                "Version State": "Latest",
                "Vulnerabilities": "1",
                "Status": "Alert"
            },
            {
                "Component": "Plugin: youtube-embed-plus",
                "Version": "Unknown",
                "Version State": "N/A",
                "Vulnerabilities": "2 (potential)",
                "Status": "Warning"
            }
        ],
        "line": "WPScan result summary: alerts=1, warnings=5, infos=9, error=0"
    },
    "error": null
}
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
  --inline              display only one line like: "WPScan result summary: alerts={}, warnings={}, infos={}, error={}".
  --no_warnings         do not display warnings, only summary and alerts. Implies --no_infos.
  --no_infos            do not display informations and findinds.
  --no_summary          do not display the summary of issues.
  --show_all            show all findings details (found by, confidence, confirmed by).
  --false_positive String [String ...]
                        consider all matching messages as infos and add "[False positive]" prefix.
  --version             print wpscan_out_parse version and exit.
  ```

Design based on [wpscan-analyze](https://github.com/lukaspustina/wpscan-analyze)