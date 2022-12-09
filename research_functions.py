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
def get_patching_history(ip_to_history, service_name, patching_versions):
    ip_to_port_ver_history = get_port_ver_history(ip_to_history, service_name, patching_versions)
    ip_to_patch_history = {}
    for ip in ip_to_port_ver_history.keys():
        for date in ip_to_port_ver_history[ip].keys():
            ports_to_version = ip_to_port_ver_history[ip][date]
            isPatched = True
            for port in ports_to_version.keys():
                if ports_to_version[port] not in patching_versions:
                    isPatched = False
                    if ip not in ip_to_patch_history:
                        ip_to_patch_history[ip] = {}
                    ip_to_patch_history[ip][date] = 0
            if len(ports_to_version) > 0 and isPatched:
                if ip not in ip_to_patch_history:
                    ip_to_patch_history[ip] = {}
                ip_to_patch_history[ip][date] = 1
    return ip_to_patch_history
            
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
    # TODO no version was thrown during Rundeck - maybe see what server didn't have version
    raise Exception("No verion was found for " + ip + " and here was the body: " + body)
                
def get_historical_data(h, patched_ips, service_name):
    datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 5)]
    dates = [d.strftime('%Y-%m-%dT%H:%M:%SZ') for d in datetimes]
    ip_to_history = {}
    for date in dates:
        responses = h.bulk_view(patched_ips, at_time = date)
        for ip in responses.keys():
            resp = responses[ip]
            if ip not in ip_to_history:
                ip_to_history[ip] = {}
            ip_to_history[ip][date] = resp
    
    with open(service_name + "_" + "history.json", 'w') as history_file:
        history_file.write(json.dumps(ip_to_history))
    return ip_to_history

def get_categories(h, queries, isPatched):
    patched_ips = []
    ases = []
    num = 0
    for query in queries:
        for page in h.search(query, pages=-1):
            num += len(page)
            for p in page:
                if isPatched and "ip" in p:
                    patched_ips.append(p["ip"])
                if "autonomous_system" in p:
                    if "asn" in p['autonomous_system']:
                        ases.append(p['autonomous_system']['asn'])
                    

    # Searches for categories associated with vulnerable instances' ASes
    with open(r'2022-05_categorized_ases.csv', newline='\n') as file:
        cat_ases = csv.DictReader(file)
        cats = {}
        for entry in cat_ases:
            for asn in ases:
                if asn == int(entry['ASN'][2:]):
                    if entry['Category 1 - Layer 1'] in cats:
                        cats[entry['Category 1 - Layer 1']] += 1
                    else:
                        cats[entry['Category 1 - Layer 1']] = 1 

    # Print out top 10 vulnerable categories
    top10 = heapq.nlargest(10, cats, key=cats.get)
    top10_to_count = {}
    for cat in top10:
        top10_to_count[cat] = cats[cat]
    return [top10_to_count, num, patched_ips]
        

def get_countries(c, queries):
    countryToNum = {}
    for query in queries:
            report = c.v2.hosts.aggregate(
                query,
                "location.country",
                num_buckets=195,
            )

            if 'buckets' in report:
                buckets = report['buckets']
                for elem in buckets:
                    if elem['key'] in countryToNum:
                        countryToNum[elem['key']] += elem['count']
                    else:
                        countryToNum[elem['key']] = elem['count']
                        
    top10 = heapq.nlargest(10, countryToNum, key=countryToNum.get)
    top10_to_count = {}
    for country in top10:
        top10_to_count[country] = countryToNum[country]
    return top10_to_count

def get_total_running_service(h, query):
    num = 0
    for page in h.search(query, pages=-1):
        num += len(page)
    return num  
    
def print_data(c, h, service, vuln_queries, patch_queries, query, patch_versions):
    # print(f"## Top 10 Countries with Vulnerable Logj4 Instances of {service} ##")
    # print(get_countries(c, vuln_queries))
    # print("\n")
    # print(f"## Top 10 Countries with Patched Logj4 Instances of {service} ##")
    # print(get_countries(c, patch_queries))
    # print("\n")

    # print(f"## Top 10 Categories with Vulnerable Logj4 Instances of {service} ##")
    # result_vuln = get_categories(h, vuln_queries)
    # print(result_vuln[0])
    # print("\n")
    # print(f"## Top 10 Categories with Patched Logj4 Instances of {service} ##")
    # result_patch = get_categories(h, patch_queries, True)
    # print(result_patch[0])
    # print("\n")
    
    # patched_ips = result_patch[2]
    file_exists = exists(service + "_" + "history.json")
    if not file_exists:
        ip_to_history = get_historical_data(h, patched_ips, service)
    else: 
        print("SHOULD BE HERE")
        f = open(service + "_" + "history.json")
        ip_to_history = json.load(f)
        f.close()
    
    isPatchedHistory = get_patching_history(ip_to_history, service, patch_versions)
    print(isPatchedHistory)
    # DO STUFF WITH ip_to_history

    # print(f"## Total Vulnerable Logj4 Instances of {service} ##")
    # print(result_vuln[1])
    # print("\n")
    # print(f"## Total Patched Logj4 Instances of {service} ##")
    # print(result_patch[1])
    # print("\n")

    # print(f"## Total Instances of {service} ##")
    # print(str(get_total_running_service(h, query)))
    # print("\n")
