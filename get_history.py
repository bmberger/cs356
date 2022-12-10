from censys.search import SearchClient
from censys.search import CensysHosts
import heapq
import csv
import json
import datetime
from os.path import exists

vulnerable_solr_vers = ['7.4.0', '7.4.1', '7.4.2', '7.4.3', '7.5.0', '7.5.1', '7.5.2', '7.5.3', '7.6.0', '7.6.1', '7.6.2', '7.6.3', '7.7.0', '7.7.1', '7.7.2', '7.7.3', '8.0.0', '8.0.1', '8.0.2', '8.0.3', '8.1.0', '8.1.1', '8.1.2', '8.1.3', '8.2.0', '8.2.1', '8.2.2', '8.2.3', '8.3.0', '8.3.1', '8.3.2', '8.3.3', '8.4.0', '8.4.1', '8.4.2', '8.4.3', '8.5.0', '8.5.1', '8.5.2', '8.5.3', '8.6.0', '8.6.1', '8.6.2', '8.6.3', '8.7.0', '8.7.1', '8.7.2', '8.7.3', '8.8.0', '8.8.1', '8.8.2', '8.8.3', '8.9.0', '8.9.1', '8.9.2', '8.9.3', '8.10.0', '8.10.1', '8.10.2', '8.10.3', '8.11.0']
patched_solr_vers = ['8.11.1', '8.11.2', '9.0.0', '9.1.0']
vulnerable_pd_vers = ['1.6.2', '1.6.1', '1.6.0', '1.5.3', '1.5.2', '1.5.1', '1.5', '1.4.5', '1.4.4', '1.4.3', '2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4', '2.0.5', '2.0.6', '2.0.7', '2.0.8', '2.0.9', '2.0.10', '2.0.11', '2.0.12', '2.0.13', '2.0.14', '2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.1.4', '2.1.5', '2.1.6', '2.1.7', '2.1.8', '2.1.9', '2.1.10', '2.1.11', '2.1.12', '2.1.13', '2.1.14', '2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4', '2.2.5', '2.2.6', '2.2.7', '2.2.8', '2.2.9', '2.2.10', '2.2.11', '2.2.12', '2.2.13', '2.2.14', '2.3.0', '2.3.1', '2.3.2', '2.3.3', '2.3.4', '2.3.5', '2.3.6', '2.3.7', '2.3.8', '2.3.9', '2.3.10', '2.3.11', '2.3.12', '2.3.13', '2.3.14', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5', '2.5.6', '2.5.7', '2.5.8', '2.5.9', '2.5.10', '2.5.11', '2.5.12', '2.5.13', '2.5.14', '2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.7.0', '2.7.1', '2.7.2', '2.7.3', '2.7.4', '2.7.5', '2.7.6', '2.7.7', '2.7.8', '2.7.9', '2.7.10', '2.7.11', '2.7.12', '2.7.13', '2.7.14', '2.8.0', '2.8.1', '2.8.2', '2.8.3', '2.8.4', '2.8.5', '2.8.6', '2.8.7', '2.8.8', '2.8.9', '2.8.10', '2.8.11', '2.8.12', '2.8.13', '2.8.14', '2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9', '2.9.10', '2.9.11', '2.9.12', '2.9.13', '2.9.14', '2.10.0', '2.10.1', '2.10.2', '2.10.3', '2.10.4', '2.10.5', '2.10.6', '2.10.7', '2.10.8', '2.10.9', '2.10.10', '2.10.11', '2.10.12', '2.10.13', '2.10.14', '2.11.0', '2.11.1', '2.11.2', '2.11.3', '2.11.4', '2.11.5', '2.11.6', '2.11.7', '2.11.8', '2.11.9', '2.11.10', '2.11.11', '2.11.12', '2.11.13', '2.11.14', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.0.7', '3.0.8', '3.0.9', '3.0.10', '3.0.11', '3.0.12', '3.0.13', '3.0.14', '3.0.15', '3.0.16', '3.0.17', '3.0.18', '3.0.19', '3.0.20', '3.0.21', '3.0.22', '3.0.23', '3.0.24', '3.0.25', '3.0.26', '3.0.27', '3.1.0', '3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5', '3.1.6', '3.2.0', '3.2.1', '3.2.2', '3.2.3', '3.2.4', '3.2.5', '3.2.6', '3.2.7', '3.2.8', '3.2.9', '3.3.0', '3.3.1', '3.3.2', '3.3.3', '3.3.4', '3.3.5', '3.3.6', '3.3.7', '3.3.8', '3.3.9', '3.3.10', '3.3.11', '3.3.12', '3.3.13', '3.3.14', '3.3.15', '3.4.0', '3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6', '3.4.7']
patched_pd_vers = ['3.3.16', '3.3.17', '3.3.18', '3.4.8', '3.4.9', '3.4.10', '4.0.0', '4.0.1', '4.1.0', '4.2.2', '4.2.3', '4.3.0', '4.3.1', '4.3.2', '4.4.0', '4.5.0', '4.6.0', '4.6.1', '4.7.0', '4.8.0']
vulnerable_neo4j_vers = ["4.4.2", "4.3.9", "4.2.13", "4.3.8", "4.4.1","4.2.12", "4.4.0", "4.3.7", "4.3.6", "4.3.5", "4.3.4", "4.2.11", "4.2.10", "4.3.3", "4.2.9", "4.3.2", "4.3.1", "4.2.8", "4.3.0", "4.2.7", "4.2.6", "4.2.5", "4.2.4", "4.2.3", "4.2.2", "4.2.1", "4.2.0"]
patched_neo4j_vers = ["4.4.3", "4.3.10", "4.2.14", "4.3.21", "4.4.13", "4.3.20", "5.1.0", "4.3.19", "4.4.12", "4.3.18", "4.4.11", "4.2.19", "4.3.17", "4.4.10", "4.3.16", "4.4.9", "4.4.15", "4.2.18", "4.3.14", "4.4.8", "4.2.17", "4.3.13", "4.4.7", "4.4.6", "4.2.16", "4.3.12", "4.4.5", "4.3.11", "4.4.4", "4.2.15", "5.2.0", "4.4.14", "4.3.22", "4.4.15"]

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
    datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 9)]
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
        ip_to_history = get_historical_data(h, ips, service, file_name)
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
    
def print_data(h, service, vuln_queries, patch_queries, query):
    # Get vulnerable and patched history
    ip_to_vuln_history = get_history(h, vuln_queries, service, False)
    ip_to_patched_history = get_history(h, patch_queries, service, True)
    
    print(f"## Total Vulnerable Logj4 Instances of {service} ##")
    print(get_total_query_size(ip_to_vuln_history))
    print("\n")
    print(f"## Total Patched Logj4 Instances of {service} ##")
    print(get_total_query_size(ip_to_patched_history))
    print("\n")

    print(f"## Total Instances of {service} ##")
    print(str(get_total_running_service(h, query)))
    print("\n")
