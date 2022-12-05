from censys.search import SearchClient
from censys.search import CensysHosts
import heapq
import csv
import json
import datetime
from os.path import exists

# Returns true or false if patched
#def isPatched(searchQuery )

# Utilized to more easily search in history data
def get_version_searches(service_name, versions):
    if "Solr Admin" == service_name:
        return [f"img/favicon.ico?_={version}" for version in versions]
    elif "Rundeck" == service_name:
        return [f"https://docs.rundeck.com/{version}" for version in version]
    elif "Neo4j" == service_name:
        return [f"\"neo4j_version\" : \"{version}\"" for version in versions]
        
def get_patching_history(ip_to_history, service_name, patching_versions):
    version_identifiers = get_version_searches(service_name, patching_versions)
    ip_to_patching_history = {}
    for ip in ip_to_history.keys():
        for date in ip_to_history[ip].keys():
            if 'services' in ip_to_history[ip][date]:
                services = ip_to_history[ip][date]['services']
                for obj in services:
                    if '_decoded' in obj and obj['_decoded'] == 'http':
                        if service_name in json.dumps(obj):
                            http_obj = obj
                            break
                else:
                    continue
                if 'http' in http_obj:
                    http = http_obj['http']
                    if 'response' in http:
                        response = http['response']
                        if 'body' in response:
                            body = response['body']
                            isPatched = False
                            for vi in version_identifiers:
                                if vi in body:
                                    # This IP is patched for this date
                                    if ip not in ip_to_patching_history:
                                        ip_to_patching_history[ip] = {}
                                    ip_to_patching_history[ip][date] = 1
                                    isPatched = True
                            if not isPatched:
                                if ip not in ip_to_patching_history:
                                    ip_to_patching_history[ip] = {}
                                ip_to_patching_history[ip][date] = 0
    return ip_to_patching_history
                
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
    # print(len(patched_ips))
    file_exists = exists(service + "_" + "history.json")
    if not file_exists:
        ip_to_history = get_historical_data(h, patched_ips, service)
    else: 
        print("SHOULD BE HERE")
        f = open(service + "_" + "history.json")
        ip_to_history = json.load(f)
        f.close()
    
    isPatchedHistory = get_patching_history(ip_to_history, service, patch_versions)
    countforfirstdate = 0
    for ip in isPatchedHistory.keys():
        if "2021-12-06T00:00:00Z" in isPatchedHistory[ip]:
            countforfirstdate += 1
    print(countforfirstdate)
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

# Main
h = CensysHosts()
c = SearchClient()

# Get Solr Admin data
vulnerable_solr_vers = ['7.4.0', '7.4.1', '7.4.2', '7.4.3', '7.5.0', '7.5.1', '7.5.2', '7.5.3', '7.6.0', '7.6.1', '7.6.2', '7.6.3', '7.7.0', '7.7.1', '7.7.2', '7.7.3', '8.0.0', '8.0.1', '8.0.2', '8.0.3', '8.1.0', '8.1.1', '8.1.2', '8.1.3', '8.2.0', '8.2.1', '8.2.2', '8.2.3', '8.3.0', '8.3.1', '8.3.2', '8.3.3', '8.4.0', '8.4.1', '8.4.2', '8.4.3', '8.5.0', '8.5.1', '8.5.2', '8.5.3', '8.6.0', '8.6.1', '8.6.2', '8.6.3', '8.7.0', '8.7.1', '8.7.2', '8.7.3', '8.8.0', '8.8.1', '8.8.2', '8.8.3', '8.9.0', '8.9.1', '8.9.2', '8.9.3', '8.10.0', '8.10.1', '8.10.2', '8.10.3', '8.11.0']
patched_solr_vers = ['8.11.1', '8.11.2', '9.0.0']
def solr_query(version):
    return f"same_service(services.http.response.html_title=`Solr Admin` and services.http.response.body: `img/favicon.ico?_={version}`)"
vulnerable_solr_vers_queries = [solr_query(version) for version in vulnerable_solr_vers]
patched_solr_vers_queries = [solr_query(version) for version in patched_solr_vers]
print_data(c, h, "Solr Admin", vulnerable_solr_vers_queries, patched_solr_vers_queries, "services.http.response.html_title=`Solr Admin`", patched_solr_vers)

# Get Pagerduty data
vulnerable_pd_vers = ['1.6.2', '1.6.1', '1.6.0', '1.5.3', '1.5.2', '1.5.1', '1.5', '1.4.5', '1.4.4', '1.4.3', '2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4', '2.0.5', '2.0.6', '2.0.7', '2.0.8', '2.0.9', '2.0.10', '2.0.11', '2.0.12', '2.0.13', '2.0.14', '2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.1.4', '2.1.5', '2.1.6', '2.1.7', '2.1.8', '2.1.9', '2.1.10', '2.1.11', '2.1.12', '2.1.13', '2.1.14', '2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4', '2.2.5', '2.2.6', '2.2.7', '2.2.8', '2.2.9', '2.2.10', '2.2.11', '2.2.12', '2.2.13', '2.2.14', '2.3.0', '2.3.1', '2.3.2', '2.3.3', '2.3.4', '2.3.5', '2.3.6', '2.3.7', '2.3.8', '2.3.9', '2.3.10', '2.3.11', '2.3.12', '2.3.13', '2.3.14', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5', '2.5.6', '2.5.7', '2.5.8', '2.5.9', '2.5.10', '2.5.11', '2.5.12', '2.5.13', '2.5.14', '2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.7.0', '2.7.1', '2.7.2', '2.7.3', '2.7.4', '2.7.5', '2.7.6', '2.7.7', '2.7.8', '2.7.9', '2.7.10', '2.7.11', '2.7.12', '2.7.13', '2.7.14', '2.8.0', '2.8.1', '2.8.2', '2.8.3', '2.8.4', '2.8.5', '2.8.6', '2.8.7', '2.8.8', '2.8.9', '2.8.10', '2.8.11', '2.8.12', '2.8.13', '2.8.14', '2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9', '2.9.10', '2.9.11', '2.9.12', '2.9.13', '2.9.14', '2.10.0', '2.10.1', '2.10.2', '2.10.3', '2.10.4', '2.10.5', '2.10.6', '2.10.7', '2.10.8', '2.10.9', '2.10.10', '2.10.11', '2.10.12', '2.10.13', '2.10.14', '2.11.0', '2.11.1', '2.11.2', '2.11.3', '2.11.4', '2.11.5', '2.11.6', '2.11.7', '2.11.8', '2.11.9', '2.11.10', '2.11.11', '2.11.12', '2.11.13', '2.11.14', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.0.7', '3.0.8', '3.0.9', '3.0.10', '3.0.11', '3.0.12', '3.0.13', '3.0.14', '3.0.15', '3.0.16', '3.0.17', '3.0.18', '3.0.19', '3.0.20', '3.0.21', '3.0.22', '3.0.23', '3.0.24', '3.0.25', '3.0.26', '3.0.27', '3.1.0', '3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5', '3.1.6', '3.2.0', '3.2.1', '3.2.2', '3.2.3', '3.2.4', '3.2.5', '3.2.6', '3.2.7', '3.2.8', '3.2.9', '3.3.0', '3.3.1', '3.3.2', '3.3.3', '3.3.4', '3.3.5', '3.3.6', '3.3.7', '3.3.8', '3.3.9', '3.3.10', '3.3.11', '3.3.12', '3.3.13', '3.3.14', '3.3.15', '3.3.16', '3.3.17', '3.3.18', '3.4.0', '3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6']
patched_pd_vers = ['3.4.7', '3.4.8', '3.4.9', '3.4.10', '4.0.0', '4.0.1', '4.1.0', '4.2.0', '4.2.1', '4.2.2', '4.2.3', '4.3.0', '4.3.1', '4.3.2', '4.4.0', '4.5.0', '4.6.0', '4.6.1', '4.7.0', '4.8.0']
def pd_query(version):
    return f"same_service(services.http.response.html_title: `Rundeck` and services.http.response.body:`https://docs.rundeck.com/{version}`)"
vulnerable_pd_vers_queries = [pd_query(version) for version in vulnerable_pd_vers]
patched_pd_vers_queries = [pd_query(version) for version in patched_pd_vers]
#print_data(c, h, "Rundeck", vulnerable_pd_vers_queries, patched_pd_vers_queries, "services.http.response.html_title: `Rundeck`", patched_pd_vers)

# Get Neo4j data
vulnerable_neo4j_vers = ["4.4.2", "4.3.9", "4.2.13", "4.3.8", "4.4.1","4.2.12", "4.4.0", "4.3.7", "4.3.6", "4.3.5", "4.3.4", "4.2.11", "4.2.10", "4.3.3", "4.2.9", "4.3.2", "4.3.1", "4.2.8", "4.3.0", "4.2.7", "4.2.6", "4.2.5", "4.2.4", "4.2.3", "4.2.2", "4.2.1", "4.2.0"]
patched_neo4j_vers = ["4.4.3", "4.3.10", "4.2.14", "4.4.14", "4.3.21", "4.4.13", "4.3.20", "5.1.0", "4.3.19", "4.4.12", "4.3.18", "4.4.11", "4.2.19", "4.3.17", "4.4.10", "4.3.16", "4.4.9", "4.4.15", "4.2.18", "4.3.14", "4.4.8", "4.2.17", "4.3.13", "4.4.7", "4.4.6", "4.2.16", "4.3.12", "4.4.5", "4.3.11", "4.4.4", "4.2.15"]

def neo4j_query(version):
    return f"same_service(services.http.response.body:`\"neo4j_version\" : \"{version}\"`)"
vulnerable_neo4j_vers_queries = [neo4j_query(version) for version in vulnerable_neo4j_vers]
patched_neo4j_vers_queries = [neo4j_query(version) for version in patched_neo4j_vers]
#print_data(c, h, "Neo4j", vulnerable_neo4j_vers_queries, patched_neo4j_vers_queries, "services.http.response.body: `neo4j`", patched_neo4j_vers)