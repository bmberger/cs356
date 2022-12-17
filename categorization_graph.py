import matplotlib.pyplot as plt
import json
import csv
import numpy as np
import get_history

kMostRecentTimestamp = "2022-12-13T05:00:00Z"

#reply should be the result of the Censys host query for a particular ip
def country_categorizer(ip, reply):
    try:
        return reply['location']['country']
    except:
        print(f"No location for {ip}")

class ASCategorizer:
    ASdb = {}
    file = ''
    def __init__(self, asdb_fname):
        self.file = open(r'/home/bberger/cs356/2022-05_categorized_ases.csv', newline='\n')
        self.ASdb = csv.DictReader(self.file)
    def get_category(self, ip, reply):
        try:
            asn = reply['autonomous_system']['asn']
        except:
            print(f"No AS for {ip}")
            return "No AS"
        l = 0
        file = open(r'/home/bberger/cs356/2022-05_categorized_ases.csv', newline='\n')
        ASdb = csv.DictReader(file)
        for entry in ASdb:
            l += 1
            #print(asn, int(entry['ASN'][2:]))
            if int(asn) == int(entry['ASN'][2:]):
                return entry['Category 1 - Layer 1']
        print(f"No category for {ip}, AS {asn}, searched {l} entries")
        return "Unknown"

def createArray(n_by_cats, top_cats):
    arr = []
    for c in top_cats:
        if c in n_by_cats:
            arr.append(n_by_cats[c])
        else:
            arr.append(0)
    return arr

#categorization is any function (ip, host reply)->string category
#patched_ips and unpatched_ips are dicts from ips to host info by date
def graph_categorization(categorization, patched_ips, unpatched_ips, n, filename):
    # Count ips by category and patched/unpatched
    total_by_category = {}
    n_patched_by_category = {}
    print(f"{len(patched_ips)} patched, {len(unpatched_ips)} unpatched")
    for ip in patched_ips:
        category = categorization(ip, patched_ips[ip][kMostRecentTimestamp])
        if category not in n_patched_by_category:
            n_patched_by_category[category] = 1
            total_by_category[category] = 1 #running first, so can't be here yet
        else:
            n_patched_by_category[category] += 1
            total_by_category[category] += 1

    n_unpatched_by_category = {}
    for ip in unpatched_ips:
        category = categorization(ip, unpatched_ips[ip][kMostRecentTimestamp])
        if category not in n_unpatched_by_category:
            n_unpatched_by_category[category] = 1
            if category not in total_by_category:
                total_by_category[category] = 1
            else:
                total_by_category[category] += 1
        else:
            n_unpatched_by_category[category] += 1
            total_by_category[category] += 1
    
    sorted_categories = sorted(total_by_category.keys(), key=lambda ip: total_by_category[ip], reverse=True)
    top_categories = sorted_categories[:n]
    print([(category, total_by_category[category]) for category in sorted_categories])

    #Adapted from https://matplotlib.org/stable/gallery/lines_bars_and_markers/barchart.html
    x = np.arange(len(top_categories))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/2, createArray(n_patched_by_category, top_categories), width, label='Patched')
    rects2 = ax.bar(x + width/2, createArray(n_unpatched_by_category, top_categories), width, label='Vulnerable')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of hosts')
    ax.set_xticks(x, top_categories)
    ax.legend()

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)

    fig.tight_layout()
    plt.savefig(filename)
    
def removeDoubleCounting(ip_to_history, ip_to_binary_history, isPatched, mostRecentDate):
    vulns = {}
    patched = {}
    for ip in ip_to_binary_history:
        if not isPatched:
            vulns[ip] = ip_to_history[ip]
        elif isPatched and ip_to_binary_history[ip][mostRecentDate] == 1:
            patched[ip] = ip_to_history[ip]
    return patched if isPatched else vulns

 # Removes counting patched servers who also have a vulnerable instance 
def graphService(service, filename_fragment, vuln_vers, patch_vers):
    # Get a dict with the following info - {ip : {date1 : 0, date2 : 1}}
    patch_file_name = service + f"_patched_{filename_fragment}.json"
    vuln_file_name = service + f"_vulnerable_{filename_fragment}.json"
    
    f1 = open(patch_file_name)
    patched_ip_to_history = json.load(f1)
    f1.close()
    
    f2 = open(vuln_file_name)
    vuln_ip_to_history = json.load(f2)
    f2.close()
    
    vuln_binary_history = get_history.get_binary_history(vuln_ip_to_history, service, vuln_vers)
    patch_binary_history = get_history.get_binary_history(patched_ip_to_history, service, patch_vers)
    
    updated_patched_ip_to_history = removeDoubleCounting(patched_ip_to_history, patch_binary_history, True, kMostRecentTimestamp)
    updated_vuln_ip_to_history = removeDoubleCounting(vuln_ip_to_history, vuln_binary_history, False, kMostRecentTimestamp)
    
    # Graph the service's categories
    categorizer = ASCategorizer("2022-05_categorized_ases.csv")
    graph_categorization(lambda ip, reply: categorizer.get_category(ip, reply), updated_patched_ip_to_history, updated_vuln_ip_to_history, 10, service + "_categories.pdf")

    # Graph the service's countries
    graph_categorization(country_categorizer, updated_patched_ip_to_history, updated_vuln_ip_to_history, 10, service + "_countries.pdf")

categorizer = ASCategorizer("2022-05_categorized_ases.csv")
# graphService("Solr Admin", "curresp", get_history.vulnerable_solr_vers, get_history.patched_solr_vers)
# graphService("Rundeck", "curresp", get_history.vulnerable_pd_vers, get_history.patched_pd_vers)
graphService("Neo4j", "curresp",  get_history.vulnerable_neo4j_vers, get_history.patched_neo4j_vers)

# TODO: look at '52.49.89.38'



    

