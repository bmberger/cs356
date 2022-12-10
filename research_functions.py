from censys.search import SearchClient
from censys.search import CensysHosts
import heapq
import csv
import json
import datetime
from os.path import exists

def get_version_str_end(service_name):
    if "Solr Admin" == service_name:
        return ["img/favicon.ico?_=", "\""]
    elif "Rundeck" == service_name:
        return ["https://docs.rundeck.com/", "/"]
    elif "Neo4j" == service_name:
        return ["\"neo4j_version\" : \"", "\""]

# If any port's service is vulnerable, the IP is considered vulnerable.
# Only if all of the port's services are patched, the IP is considered patched.
def get_binary_history(ip_to_history, service_name, versions):
    ip_to_port_ver_history = get_port_ver_history(ip_to_history, service_name, patching_versions)
    ip_to_binary_history = {}
    for ip in ip_to_port_ver_history.keys():
        for date in ip_to_port_ver_history[ip].keys():
            ports_to_version = ip_to_port_ver_history[ip][date]
            isInVersions = True
            for port in ports_to_version.keys():
                if ports_to_version[port] not in versions:
                    isInVersions = False
                    if ip not in ip_to_binary_history:
                        ip_to_binary_history[ip] = {}
                    ip_to_binary_history[ip][date] = 0
            if len(ports_to_version) > 0 and isInVersions:
                if ip not in ip_to_binary_history:
                    ip_to_binary_history[ip] = {}
                ip_to_binary_history[ip][date] = 1
    return ip_to_binary_history

# Parses through ip_to_history to accurately categorize the server via port-granularity           
def get_port_ver_history(ip_to_history, service_name, patching_versions):
    ip_to_port_ver_history = {}
    for ip in ip_to_history.keys():
        for date in ip_to_history[ip].keys():
            if 'services' in ip_to_history[ip][date]:
                services = ip_to_history[ip][date]['services']
                target_instances = filter(lambda service : is_target_service_entry(service_name, service), services)
                ports_to_body = get_ports_to_body(target_instances)
                ports_to_version = {port : extract_version(ports_to_body[port], service_name, ip) for port in ports_to_body}
                if ip not in ip_to_port_ver_history:
                    ip_to_port_ver_history[ip] = {}
                ip_to_port_ver_history[ip][date] = ports_to_version
    return ip_to_port_ver_history

# Gets a dict of ports to their bodies 
def get_ports_to_body(solr_instances):
    ports_to_body = {}
    for inst in solr_instances:
        if 'port' in inst:
            port = inst['port']
        else: 
            raise Exception("No port found.")
        
        if 'http' in inst:
            http = inst['http']
            if 'response' in http:
                resp = http['response']
                if 'body' in resp:
                    if port not in ports_to_body:
                        ports_to_body[port] = resp['body']
    return ports_to_body

# Filters out which ports we care about 
def is_target_service_entry(service_name, obj):
    if '_decoded' in obj and obj['_decoded'] == 'http':
        http_obj = obj
        if 'http' in http_obj:
            http = http_obj['http']
            if 'response' in http:
                response = http['response']
                if service_name != "Neo4j":
                    version_query = get_version_str_end(service_name)[0]
                    if 'html_title' in response:
                        return (service_name.lower() in response['html_title'].lower()) and version_query in response['body']
                else:
                    if 'body' in response:
                        return "\"neo4j_version\" : \"" in response['body'].lower()
    return False

# Extract version of that port's service
def extract_version(body, service_name, ip):
    pair = get_version_str_end(service_name)
    search_string = pair[0]
    end_string = pair[1]
    result = body.find(search_string)
    if result > 0:
        end = body.find(end_string, result + len(search_string))
        return body[result + len(search_string) : end]
    raise Exception("No verion was found for " + ip + " and here was the body: " + body)
                
# Gets a dict from ip to a dict of dates to that ip's response for that date
def get_historical_data(h, ips, service_name, file_name):
    datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 5)]
    dates = [d.strftime('%Y-%m-%dT%H:%M:%SZ') for d in datetimes]
    ip_to_history = {}
    for date in dates:
        responses = h.bulk_view(ips, at_time = date)
        for ip in responses.keys():
            resp = responses[ip]
            if ip not in ip_to_history:
                ip_to_history[ip] = {}
            ip_to_history[ip][date] = resp
    
    with open(file_name, 'w') as history_file:
        history_file.write(json.dumps(ip_to_history))
    return ip_to_history

# Gets all of the current IPs associated with each query in queries
def get_ips(h, queries):
    ips = []
    for query in queries:
        for page in h.search(query, pages=-1):
            for p in page:
                if "ip" in p:
                    ips.append(p["ip"])
    return ips

# Combines get_ips and get_historical_data while also checking if that file already exists
def get_history(h, queries, service, isPatched):
    ips = get_ips(h, queries)
    file_name = service + "_patched_history.json" if isPatched else service + "_vulnerable_history.json"
    
    file_exists = exists(file_name)
    if not file_exists:
        ip_to_history = get_historical_data(h, patched_ips, service, file_name)
    else: 
        f = open(file_name)
        ip_to_history = json.load(f)
        f.close()
    return ip_to_history

# Gets the total number of ips associated with dict (i.e. how many vulnerable IPs are there?)
def get_total_query_size(ip_to_history):
    return len(ip_to_history.keys())

# Gets total number running a particular service
def get_total_running_service(h, query):
    num = 0
    for page in h.search(query, pages=-1):
        num += len(page)
    return num  
    
def print_data(c, h, service, vuln_queries, patch_queries, query, patch_versions, vuln_versions):
    # Get vulnerable and patched history
    ip_to_vuln_history = get_history(h, vuln_queries, service, False)
    ip_to_patched_history = get_history(h, patch_queries, service, True)
    
    # Get binary representation of patching history for both curr vuln and patched IPs
    ip_to_patched_binary_history = get_binary_history(ip_to_patched_history, service, patch_versions)
    ip_to_vuln_binary_history = get_binary_history(ip_to_vuln_history, service, vuln_versions)
    
    print(f"## Total Vulnerable Logj4 Instances of {service} ##")
    print(get_total_query_size(ip_to_vuln_history))
    print("\n")
    print(f"## Total Patched Logj4 Instances of {service} ##")
    print(get_total_query_size(ip_to_patched_history))
    print("\n")

    print(f"## Total Instances of {service} ##")
    print(str(get_total_running_service(h, query)))
    print("\n")
