import matplotlib.pyplot as plt
import json
import csv

kMostRecentTimestamp = '2022-12-09T00:00:00Z'

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
            return ""
        l = 0
        file = open(r'/home/bberger/cs356/2022-05_categorized_ases.csv', newline='\n')
        ASdb = csv.DictReader(file)
        for entry in ASdb:
            l += 1
            #print(asn, int(entry['ASN'][2:]))
            if int(asn) == int(entry['ASN'][2:]):
                return entry['Category 1 - Layer 1']
        print(f"No category for {ip}, AS {asn}, searched {l} entries")
        return ""


#categorization is any function (ip, host reply)->string category
#patched_ips and unpatched_ips are dicts from ips to host info by date
def graph_categorization(categorization, patched_ips, unpatched_ips, n):
    # Count ips by category and patched/unpatched
    total_by_category = {}
    n_patched_by_category = {}
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

    plt.bar(top_categories, [total_by_category[c] for c in top_categories])
    plt.savefig("test2.png")

service = "Rundeck"
path = "/home/bberger/cs356/"
f = open(path + service + "_patched_history.json")
ip_to_history = json.load(f)
#print(ip_to_history[list(ip_to_history.keys())[2]]['2022-12-03T00:00:00Z']['location']['country'])
categorizer = ASCategorizer("2022-05_categorized_ases.csv")
graph_categorization(lambda ip, reply: categorizer.get_category(ip, reply), ip_to_history, {}, 10)

# TODO: look at '52.49.89.38'



    

