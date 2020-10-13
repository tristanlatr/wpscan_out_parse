import json
import re
from string import Template


def format_results(results, format, warnings=True, infos=True, nocolor=False):
    """
    Format the results dict into a "html", "cli" or "json" string.

    - results: resutlts dict objject.
    - format: in `"html"`, `"cli"` or `"json"`
    """
    if format == "json":
        return json.dumps(dict(results), indent=4)
    else:
        return build_message(
            dict(results),
            format=format,
            warnings=warnings,
            infos=infos,
            nocolor=nocolor,
        )


def build_message(results, warnings=True, infos=True, format="cli", nocolor=False):
    """Build mail message text base on report and warnngs and info switch"""
    message = ""
    if results["error"]:
        message += "An error occurred.\n".replace(
            "\n", "<br/>\n" if format == "html" else "\n"
        )
    elif results["alerts"]:
        message += "Vulnerabilities have been detected by WPScan.\n".replace(
            "\n", "<br/>\n" if format == "html" else "\n"
        )
    elif results["warnings"]:
        message += "Issues have been detected by WPScan.\n".replace(
            "\n", "<br/>\n" if format == "html" else "\n"
        )

    if results["summary"] and results["summary"]["line"]:
        summary = []

        if format == "cli":
            if results["summary"]["table"]:
                summary.append(
                    format_summary_ascii_table(
                        results["summary"]["table"],
                        results["summary"]["line"],
                        nocolor=nocolor,
                    )
                )
            else:
                summary.append(results["summary"]["line"])
        elif format == "html":
            if results["summary"]["table"]:
                summary.append(
                    format_summary_html(
                        results["summary"]["table"],
                        results["summary"]["line"],
                        nocolor=nocolor,
                    )
                )
            else:
                summary.append(results["summary"]["line"])
        else:
            raise ValueError("format can only be 'cli' or 'html'")

        message += format_issues(
            "Summary", summary, format=format, apply_br_tab_replace_on_issues=False
        )

    if results["error"]:
        message += "\n".replace("\n", "<br/>\n" if format == "html" else "\n")
        message += format_issues("Error", [results["error"]], format=format)

    if results["alerts"]:
        message += "\n".replace("\n", "<br/>\n" if format == "html" else "\n")
        message += format_issues("Alerts", results["alerts"], format=format)

    if results["warnings"] and warnings:
        message += "\n".replace("\n", "<br/>\n" if format == "html" else "\n")
        message += format_issues("Warnings", results["warnings"], format=format)

    if results["infos"] and infos:
        message += "\n".replace("\n", "<br/>\n" if format == "html" else "\n")
        message += format_issues("Informations", results["infos"], format=format)

    return message


def format_issues(title, issues, format="cli", apply_br_tab_replace_on_issues=True):
    """Format one block of issues to text with the title"""
    message = ""
    if issues:
        if format == "html":
            message += (
                "<br/>\n&nbsp;&nbsp;&nbsp;&nbsp;%s<br/>\n&nbsp;&nbsp;&nbsp;&nbsp;%s<br/>\n<br/>\n"
                % (title, "-" * len(title))
            )
            message += "<br/>\n<br/>\n".join(
                [
                    replace(issue, {"\n": "<br/>\n", "\t": "&nbsp;&nbsp;&nbsp;&nbsp;"})
                    if format == "html" and apply_br_tab_replace_on_issues
                    else issue
                    for issue in issues
                ]
            )
        else:
            message += "\n\t%s\n\t%s\n\n" % (title, "-" * len(title)) + "\n\n".join(
                issues
            )
    return message


def get_table_cell_color(col, val, ansi=False):
    color = ""
    if col == "Version State":
        if ansi:
            color = (
                "yellow"
                if "Outdated" in val
                else "green"
                if "Latest" in val
                else "default"
            )
        else:
            color = (
                "#cccc00"
                if "Outdated" in val
                else "#228B22"
                if "Latest" in val
                else "#000000"
            )
    elif col == "Vulnerabilities":
        if ansi:
            color = "red" if val.isnumeric() and int(val) > 0 else "default"
        else:
            color = "#ba0000" if val.isnumeric() and int(val) > 0 else "#000000"
    elif col == "Status":
        if ansi:
            color = (
                "red"
                if "Alert" in val
                else "yellow"
                if "Warning" in val
                else "green"
                if "Ok" in val
                else "gray"
                if "Unknown" in val
                else "default"
            )
        else:
            color = (
                "#BA0000"
                if "Alert" in val
                else "#cccc00"
                if "Warning" in val
                else "#008000"
                if "Ok" in val
                else "#808080"
                if "Unknown" in val
                else "#000000"
            )
    return color


def format_summary_ascii_table(table, line, nocolor=False):
    """Return a nice string table
    Author: Thierry Husson - Use it as you want but don't blame me.
    """
    try:
        from colors import color, ansilen
    except ImportError:
        nocolor = True

    myDict = table
    colList = ["Component", "Version", "Version State", "Vulnerabilities", "Status"]
    myList = [colList]  # 1st row = header
    for item in myDict:
        myList.append(
            [
                str(
                    item[col]
                    if nocolor and item[col] is not None
                    else color(
                        str(item[col]),
                        fg=get_table_cell_color(col, item[col], ansi=True),
                    )
                    if nocolor == False and item[col] is not None
                    else ""
                )
                for col in colList
            ]
        )
    colSize = [max(map(len if nocolor else ansilen, col)) for col in zip(*myList)]
    formatStr = " | ".join(["{{:<{}s}}".format(i) for i in colSize])
    myList.insert(1, ["-" * i for i in colSize])  # Seperating line
    string = "\n".join(
        formatStr.format(
            *[
                e.ljust(colSize[i] + (0 if nocolor else int(len(e) - ansilen(e))), " ")
                for (i, e) in enumerate(item)
            ]
        )
        for item in myList
    )
    return string + "\n\n" + line


def format_summary_html(table, line, nocolor):
    row_fmt = """      <tr>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
        <td>{}</td>
    </tr>
    """
    table_rows = ""
    for row in table:
        table_rows += row_fmt.format(
            row["Component"],
            row["Version"],
            # Determine version state
            '<span style="color:{color}">{vulns}</span>'.format(
                vulns=row["Version State"],
                color="#000000"
                if nocolor
                else get_table_cell_color("Version State", row["Version State"]),
            ),
            # Determine vulns color
            '<span style="color:{color}">{vulns}</span>'.format(
                vulns=row["Vulnerabilities"],
                color="#000000"
                if nocolor
                else get_table_cell_color("Vulnerabilities", row["Vulnerabilities"]),
            ),
            # Determine status color
            '<b style="color:{color}">{status}</b>'.format(
                status=row["Status"],
                color="#000000"
                if nocolor
                else get_table_cell_color("Status", row["Status"]),
            ),
        )

    return """<table>
        <tr>
            <th>Component</th>
            <th>Version</th>
            <th>Version State</th>
            <th>Vulnerabilities</th>
            <th>Status</th>
        </tr>
    {}
    </table>
    <br/>{}""".format(
        table_rows, line
    )


def replace(text, conditions):
    """Multiple replacements helper method.  Stolen on the web"""
    rep = conditions
    rep = dict((re.escape(k), rep[k]) for k in rep)
    pattern = re.compile("|".join(rep.keys()))
    text = pattern.sub(lambda m: rep[re.escape(m.group(0))], text)
    return text
