import csv
import jinja2
import xml.etree.ElementTree as xml

from core.redis import rds
from core.utils import Utils
from version import VERSION

utils = Utils()

def generate_csv(data):  
  filename = 'report-{}-{}.csv'.format(utils.generate_uuid(), utils.get_date())
  with open('reports' + '/' + filename, mode='w') as csv_file:
    fieldnames = ['#', 'ip', 'port', 'rule_id', 'rule_severity', 'rule_description', 'rule_rule_confirm', 'rule_mitigation']
    writer = csv.writer(csv_file)
    writer.writerow(fieldnames)
    
    row_num = 0
    for k, i in data.items():
      row_num += 1
      writer.writerow([row_num, 
                      i['ip'], 
                      i['port'], 
                      i['rule_id'], 
                      utils.sev_to_human(i['rule_sev']), 
                      i['rule_desc'], 
                      i['rule_confirm'], 
                      i['rule_mitigation']])
  
  return filename

def generate_html(vulns, conf):
  vuln_count = {0:0, 1:0, 2:0, 3:0, 4:0}
  filename = 'report-{}-{}.html'.format(utils.generate_uuid(), utils.get_date())
  templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
  templateEnv = jinja2.Environment(loader=templateLoader)
  TEMPLATE_FILE = "report_template.html"
  template = templateEnv.get_template(TEMPLATE_FILE)
  
  for k, v in vulns.items():
    vuln_count[v['rule_sev']] += 1
  
  sorted_vulns = {k: v for k, v in sorted(vulns.items(), key=lambda item: item[1]['rule_sev'], reverse=True)}
  
  body = {
        'conf': conf,
        'vulns': sorted_vulns,
        'vuln_count':vuln_count,
        'version':VERSION,
  }
  html = template.render(json_data=body) 
  
  f = open('reports/' + filename, "w")
  f.write(html)
  f.close()
  
  return filename

def generate_txt(vulns):
  filename = 'report-{}-{}.txt'.format(utils.generate_uuid(), utils.get_date())
  data = ''
  for key, value in vulns.items():
    for k, v in value.items():
      data += '{}:{}\n'.format(k,v)
    data += '\n'
  
  f = open('reports/' + filename, "w")
  f.write(data)
  f.close()
  
  return filename
  
def generate_xml(vulns):
  filename = 'report-{}-{}.xml'.format(utils.generate_uuid(), utils.get_date())
  root = xml.Element("Vulnerabilities")
  for key, value in vulns.items():
    vuln_element = xml.Element(key)
    root.append(vuln_element)

    ip = xml.SubElement(vuln_element, "ip")
    ip.text =  value['ip']

    port = xml.SubElement(vuln_element, "port")
    port.text = str(value['port'])

    domain = xml.SubElement(vuln_element, "domain")
    domain.text = value['domain']

    sev = xml.SubElement(vuln_element, "severity")
    sev.text = utils.sev_to_human(value['rule_sev'])

    description = xml.SubElement(vuln_element, "description")
    description.text = value['rule_desc']

    confirm = xml.SubElement(vuln_element, "confirm")
    confirm.text = value['rule_confirm']
    
    details = xml.SubElement(vuln_element, "details")
    details.text = value['rule_details']

    mitigation = xml.SubElement(vuln_element, "mitigation")
    mitigation.text = value['rule_mitigation']

  data = xml.tostring(root)
  f = open('reports/' + filename, "w")
  f.write(data.decode('utf-8'))
  f.close()

  return filename