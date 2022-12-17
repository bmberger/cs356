import matplotlib.pyplot as plt
import numpy as np
import get_history
import datetime
import json

# y-axis: percent patched Total
# x-axis: date
# starting point of each line is when those services came online

datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 9)]
x_dates = [d.strftime('%Y-%m-%dT%H:%M:%SZ') for d in datetimes]



def graphService(service, vers, isPatched):
    # Get a dict with the following info - {ip : {date1 : 0, date2 : 1}}
    file_name = "../../bberger/cs356/" + service + ("_patched_history.json" if isPatched else "_vulnerable_history.json")
    f = open(file_name)
    ip_to_history = json.load(f)
    f.close()
    patched_history = get_history.get_binary_history(ip_to_history, service, vers)
    
    # Graph the service's patched or unpatched history
    graph(patched_history, isPatched, service)


n_patched_by_start_date = {} # service to dict (start date to n currently patched)
n_unpatched_by_start_date = {} # service to dict (start date to n currently vulnerable)


def graph(patched_history, use_patched, service):
    patched_instance_counts = {} #first layer is start date, second is actual date
    unpatched_instance_counts = {}
    for start_date in x_dates:
        patched_instance_counts[start_date] = {}
        unpatched_instance_counts[start_date] = {}
        for date in x_dates:
            patched_instance_counts[start_date][date] = 0
            unpatched_instance_counts[start_date][date] = 0

    if use_patched:
        n_patched_by_start_date[service] = {start_date: 0 for start_date in x_dates}
        total_found_by_start_date = n_patched_by_start_date[service]
    else:
        n_unpatched_by_start_date[service] = {start_date: 0 for start_date in x_dates}
        total_found_by_start_date = n_unpatched_by_start_date[service]


    start_dates_by_ip = {}
    for date in x_dates:
        for ip in patched_history:
            if date in patched_history[ip]: # Choses the earliest address via outer loop
                if not ip in start_dates_by_ip:
                    start_dates_by_ip[ip] = date
                    total_found_by_start_date[date] += 1
                if patched_history[ip][date] == 0:
                    unpatched_instance_counts[start_dates_by_ip[ip]][date] += 1
                else:
                    patched_instance_counts[start_dates_by_ip[ip]][date] += 1     
    #print(start_dates_by_ip)
    #print(unpatched_instance_counts)
    #print(patched_instance_counts)

    print(f"-----{service} {'patched' if use_patched else 'vulnerable'} ---------------------")
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

    plt.savefig(f"/home/kmehall/{service}-{'patched' if use_patched else 'vulnerable'}.pdf")


graphService("Solr Admin", get_history.patched_solr_vers, True)
graphService("Solr Admin", get_history.vulnerable_solr_vers, False)
graphService("Rundeck", get_history.patched_pd_vers, True)
graphService("Rundeck", get_history.vulnerable_pd_vers, False)
graphService("Neo4j", get_history.patched_neo4j_vers, True)
graphService("Neo4j", get_history.vulnerable_neo4j_vers, False)

print(n_patched_by_start_date)
print(n_unpatched_by_start_date)

for service in ["Solr Admin", "Rundeck", "Neo4j"]:
    #Adapted from https://matplotlib.org/stable/gallery/lines_bars_and_markers/barchart.html
    x = np.arange(len(datetimes))  # the label locations
    width = 0.35  # the width of the bars

    patched_bars = [n_patched_by_start_date[service][date] for date in x_dates]
    unpatched_bars = [n_unpatched_by_start_date[service][date] for date in x_dates]

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/2, patched_bars, width, label='Currently Patched')
    rects2 = ax.bar(x + width/2, unpatched_bars, width, label='Currently Vulnerable')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of hosts')
    ax.set_xlabel(f'First observed running an instance of {service}')
    ax.set_xticks(x, [d.strftime('%Y-%m') for d in datetimes])
    plt.xticks(rotation=45, ha='right')
    ax.legend()

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)

    fig.tight_layout()
    plt.savefig(f"{service}_start_dates.pdf")