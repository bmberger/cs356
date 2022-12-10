import matplotlib.pyplot as plt
# import numpy as np
import get_history
import datetime
import json

# y-axis: percent patched Total
# x-axis: date
# starting point of each line is when those services came online

datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 9)]
x_dates = [d.strftime('%Y-%m-%dT%H:%M:%SZ') for d in datetimes]

graphService("Solr Admin", get_history.patched_solr_vers, True)
graphService("Solr Admin", get_history.vulnerable_solr_vers, False)
graphService("Rundeck", get_history.patched_pd_vers, True)
graphService("Rundeck", get_history.vulnerable_pd_vers, False)
graphService("Neo4j", get_history.patched_neo4j_vers, True)
graphService("Neo4j", get_history.vulnerable_neo4j_vers, False)

def graphService(service, vers, isPatched):
    # Get a dict with the following info - {ip : {date1 : 0, date2 : 1}}
    file_name = service + "_patched_history.json" if isPatched else service + "_vulnerable_history.json"
    f = open(file_name)
    ip_to_history = json.load(f)
    f.close()
    patched_history = get_history.get_patching_history(ip_to_history, service, vers)
    
    # Graph the service's patched or unpatched history
    graph(patched_history)
            
def graph(patched_history):
    patched_instance_counts = {} #first layer is start date, second is actual date
    unpatched_instance_counts = {}
    for start_date in x_dates:
        patched_instance_counts[start_date] = {}
        unpatched_instance_counts[start_date] = {}
        for date in x_dates:
            patched_instance_counts[start_date][date] = 0
            unpatched_instance_counts[start_date][date] = 0

    start_dates_by_ip = {}
    for date in x_dates:
        for ip in patched_history:
            if date in patched_history[ip]: # Choses the earliest address via outer loop
                if not ip in start_dates_by_ip:
                    start_dates_by_ip[ip] = date
                if patched_history[ip][date] == 0:
                    unpatched_instance_counts[start_dates_by_ip[ip]][date] += 1
                else:
                    patched_instance_counts[start_dates_by_ip[ip]][date] += 1     
    #print(start_dates_by_ip)
    #print(unpatched_instance_counts)
    #print(patched_instance_counts)

    patched_data = [[patched_instance_counts[start][date] for date in x_dates] for start in x_dates]
    print(patched_data)
    unpatched_data = [[unpatched_instance_counts[start][date] for date in x_dates] for start in x_dates]
    print(unpatched_data)
    ratio = [[patched_instance_counts[start][date] / (unpatched_instance_counts[start][date] + patched_instance_counts[start][date] + 0.00001) for date in x_dates] for start in x_dates]
    print(ratio)

    for date in x_dates[-1:]:
        print(date)
        date_unpatched = [unpatched_instance_counts[start][date] for start in x_dates]
        print("unpatched from patched search", date_unpatched)
        print("total", sum(date_unpatched))

        date_patched = [patched_instance_counts[start][date] for start in x_dates]
        print("patched from patched search", date_patched)
        print("total", sum(date_patched))

    fig = plt.figure()
    ax = fig.add_subplot()

    for i in range(len(x_dates)):
        ax.plot(datetimes[i:], ratio[i][i:], label=datetimes[i])
    ax.legend(ncol=2, title="Instance first observed")

    plt.savefig(f"/home/kmehall/{service}.png", dpi=300)