# WPScan Output Parse

**`wpscan_out_parse` is a Python parser for WPScan output files** (JSON and CLI).  
It analyze vulnerabilities, miscellaneous alerts and warnings and other findings.  

<a href="https://github.com/tristanlatr/wpscan_out_parse/actions" target="_blank"><img src="https://github.com/tristanlatr/wpscan_out_parse/workflows/test/badge.svg"></a>
<a href="https://codecov.io/gh/tristanlatr/wpscan_out_parse" target="_blank"><img src="https://codecov.io/gh/tristanlatr/wpscan_out_parse/branch/master/graph/badge.svg"></a>
<a href="https://pypi.org/project/wpscan-out-parse/" target="_blank"><img src="https://badge.fury.io/py/wpscan-out-parse.svg"></a>

### Features
- Support WPScan JSON and CLI output files
- Return results in CLI, JSON and HTML output format
- Generate a summary table of your wordpress component containing version and vulnerabilities  
- Divide the results in "Alerts", "Warnings" and "Informations"
- Additionnal alerts depending of finding type (SQL dump, etc.)  
- Signal result via exit code
- Ignore messages based on false positives strings 
- Simple Python library usage

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

### As a Python library
```python
import wpscan_out_parse
results=wpscan_out_parse.parse_results_from_file('./test/output_files/wordpress_many_vuln.json')
print(results)
```

See [docs.md](https://github.com/tristanlatr/wpscan_out_parse/blob/master/DOCS.md) for more technicals details on Python objects and library usage.  

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
python3 -m wpscan_out_parse ./test/output_files/wordpress_no_vuln.json --format html            
<div>Issues have been detected by WPScan.<br/>
<br/>
&nbsp;&nbsp;&nbsp;&nbsp;Summary<br/>
&nbsp;&nbsp;&nbsp;&nbsp;-------<br/>
<br/>
<table>
        <tr>
            <th>Component</th>
            <th>Version</th>
            <th>Version State</th>
            <th>Vulnerabilities</th>
            <th>Status</th>
        </tr>
          <tr>
        <td>WordPress 5.2.2 (2019-06-18)</td>
        <td>5.2.2</td>
        <td>Latest</td>
        <td>0</td>
        <td><b style="color:#228B22">Ok</b></td>
    </tr>
          <tr>
        <td>Main Theme: customizr</td>
        <td>4.1.42</td>
        <td>Latest</td>
        <td>0</td>
        <td><b style="color:#FFD700">Warning</b></td>
    </tr>
          <tr>
        <td>Plugin: youtube-embed-plus</td>
        <td>Unknown</td>
        <td>N/A</td>
        <td>0</td>
        <td><b style="color:#228B22">Ok</b></td>
    </tr>
    
    </table>
    <br/>WPScan result summary: alerts=0, warnings=2, infos=10, error=0<br/>
<br/>
&nbsp;&nbsp;&nbsp;&nbsp;Warnings<br/>
&nbsp;&nbsp;&nbsp;&nbsp;--------<br/>
<br/>
Main Theme: customizr<br/>
An error log file has been found: https://www.sample-owasp-wp.com/wp-content/themes/customizr/error_log<br/>
Readme: https://www.sample-owasp-wp.com/wp-content/themes/customizr/readme.txt<br/>
Version: 4.1.42 (up to date)<br/>
Style CSS: https://www.sample-owasp-wp.com/wp-content/themes/customizr/style.css?ver=4.1.42<br/>
<br/>
Upload directory has listing enabled: https://www.sample-owasp-wp.com/wp-content/uploads/<br/>
<br/>
&nbsp;&nbsp;&nbsp;&nbsp;Informations<br/>
&nbsp;&nbsp;&nbsp;&nbsp;------------<br/>
<br/>
Wordpress version: 5.2.2 (up to date)<br/>
Release Date: 2019-06-18<br/>
<br/>
Plugin: youtube-embed-plus<br/>
The version could not be determined (latest is 13.1)<br/>
<br/>
Headers<br/>
Interesting entries: <br/>
- server: nginx/1.14.1<br/>
<br/>
Robots_Txt<br/>
<br/>
Xmlrpc<br/>
References: <br/>
- Url: http://codex.wordpress.org/XML-RPC_Pingback_API<br/>
- Metasploit: https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner<br/>
- Metasploit: https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos<br/>
- Metasploit: https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login<br/>
- Metasploit: https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access<br/>
<br/>
Readme<br/>
<br/>
This site has 'Must Use Plugins': https://www.sample-owasp-wp.com/wp-content/mu-plugins/<br/>
References: <br/>
- Url: http://codex.wordpress.org/Must_Use_Plugins<br/>
<br/>
Wp_Cron<br/>
References: <br/>
- Url: https://www.iplocation.net/defend-wordpress-from-ddos<br/>
- Url: https://github.com/wpscanteam/wpscan/issues/1299<br/>
<br/>
Scanned with WordPress Security Scanner by the WPScan Team<br/>
Version: 3.5.4<br/>
<br/>
Target URL: https://www.sample-owasp-wp.com/<br/>
Target IP: None<br/>
Effective URL: https://www.sample-owasp-wp.com/</div>
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
