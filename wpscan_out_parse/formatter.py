import json
import re
from .parser import WPScanJsonParser

def format_results(results, format):
    if format == 'json':
        return json.dumps(dict(results), indent=4)
    else:
        return build_message(dict(results), format=format)

def build_message(results, warnings=True, infos=True, format='cli'):
    '''Build mail message text base on report and warnngs and info switch'''
    message=""
    if results['error'] : message += "\nAn error occurred.\n"
    elif results['alerts'] : message += "\nVulnerabilities have been detected by WPScan.\n"
    elif results['warnings']: message += "\nIssues have been detected by WPScan.\n"

    if results['summary'] and results['summary']['line']:
        summary=[]
        
        if format=='cli':
            if results['summary']['table']:
                summary.append(format_summary_ascii_table(results['summary']['table'], results['summary']['line']))
            else:
                summary.append(results['summary']['line'])
        elif format=='html':
            if results['summary']['table']:
                summary.append(format_summary_html(results['summary']['table'], results['summary']['line']))
            else:
                summary.append(results['summary']['line'])
        else: 
            raise ValueError("format can only be 'cli' or 'html'")
        
        message += format_issues_cli('Summary', summary)

    if results['error']: 
        message += "\n"
        message += format_issues_cli('Error',[results['error']])
        
    if results['alerts']: 
        message += "\n"
        message += format_issues_cli('Alerts',results['alerts'])
        
    if results['warnings'] and warnings: 
        message += "\n"
        message += format_issues_cli('Warnings',results['warnings'])
        
    if results['infos'] and infos: 
        message += "\n"
        message += format_issues_cli('Informations',results['infos'])
        
    message += "\n"
    if format=='html':
        message='<div>'+replace(message, {'\n':'<br/>', '\t':'&nbsp;&nbsp;&nbsp;&nbsp;'})+'</div>'
    return message

def format_issues_cli(title, issues):
    '''Format one block of issues to text with the title'''
    message=""
    if issues:
        message += "\n\t%s\n\t%s\n\n"%(title, '-'*len(title))+"\n\n".join(issues)
    return message

def format_summary_ascii_table(table, line):
    """ Return a nice string table
    Author: Thierry Husson - Use it as you want but don't blame me.
    """
    myDict=table
    colList = ['Component', 'Version', 'Version State', 'Vulnerabilities', 'Status']
    myList = [colList] # 1st row = header
    for item in myDict: myList.append([str(item[col] if item[col] is not None else '') for col in colList])
    colSize = [max(map(len,col)) for col in zip(*myList)]
    formatStr = ' | '.join(["{{:<{}}}".format(i) for i in colSize])
    myList.insert(1, ['-' * i for i in colSize]) # Seperating line
    string='\n'.join(formatStr.format(*item) for item in myList)
    return string+'\n\n'+line

def format_summary_html(table, line):
    row_fmt  = '''<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'''
    table_rows=""
    for row in table:
        row_fmt.format(
            row['Component'],
            row['Version'],
            row['Version State'],
            row['Vulnerabilities'],
            '<b style="color:{color}">{status}</b>'.format(status=row['Status'], color='#8B0000' if row['Status']=='Alert' else '#FFD700' if row['Status'] == 'Warning' else '#228B22'))
    return ('''<table><tr><th>Component</th><th>Version</th><th>Version State</th><th>Vulnerabilities</th><th>Status</th></tr>{}</table><br/>{}'''.format(table_rows, line))

def replace(text, conditions):
    '''Multiple replacements helper method.  Stolen on the web'''
    rep=conditions
    rep = dict((re.escape(k), rep[k]) for k in rep ) 
    pattern = re.compile("|".join(rep.keys()))
    text = pattern.sub(lambda m: rep[re.escape(m.group(0))], text)
    return text