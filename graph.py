import matplotlib.pyplot as plt
# import numpy as np
import research_functions
import datetime
import json


# y-axis: percent patched Total
# x-axis: date
# starting point of each line is when those services came online

datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 5)]
x_dates = [d.strftime('%Y-%m-%dT%H:%M:%SZ') for d in datetimes]

# Get a dict with the following info - {ip : {date1 : 0, date2 : 1}}
service = "Rundeck"
f = open(service + "_" + "history.json")
ip_to_history = json.load(f)
f.close()
vulnerable_solr_vers = ['7.4.0', '7.4.1', '7.4.2', '7.4.3', '7.5.0', '7.5.1', '7.5.2', '7.5.3', '7.6.0', '7.6.1', '7.6.2', '7.6.3', '7.7.0', '7.7.1', '7.7.2', '7.7.3', '8.0.0', '8.0.1', '8.0.2', '8.0.3', '8.1.0', '8.1.1', '8.1.2', '8.1.3', '8.2.0', '8.2.1', '8.2.2', '8.2.3', '8.3.0', '8.3.1', '8.3.2', '8.3.3', '8.4.0', '8.4.1', '8.4.2', '8.4.3', '8.5.0', '8.5.1', '8.5.2', '8.5.3', '8.6.0', '8.6.1', '8.6.2', '8.6.3', '8.7.0', '8.7.1', '8.7.2', '8.7.3', '8.8.0', '8.8.1', '8.8.2', '8.8.3', '8.9.0', '8.9.1', '8.9.2', '8.9.3', '8.10.0', '8.10.1', '8.10.2', '8.10.3', '8.11.0']
patched_solr_vers = ['8.11.1', '8.11.2', '9.0.0']
vulnerable_pd_vers = ['1.6.2', '1.6.1', '1.6.0', '1.5.3', '1.5.2', '1.5.1', '1.5', '1.4.5', '1.4.4', '1.4.3', '2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4', '2.0.5', '2.0.6', '2.0.7', '2.0.8', '2.0.9', '2.0.10', '2.0.11', '2.0.12', '2.0.13', '2.0.14', '2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.1.4', '2.1.5', '2.1.6', '2.1.7', '2.1.8', '2.1.9', '2.1.10', '2.1.11', '2.1.12', '2.1.13', '2.1.14', '2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4', '2.2.5', '2.2.6', '2.2.7', '2.2.8', '2.2.9', '2.2.10', '2.2.11', '2.2.12', '2.2.13', '2.2.14', '2.3.0', '2.3.1', '2.3.2', '2.3.3', '2.3.4', '2.3.5', '2.3.6', '2.3.7', '2.3.8', '2.3.9', '2.3.10', '2.3.11', '2.3.12', '2.3.13', '2.3.14', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.5.0', '2.5.1', '2.5.2', '2.5.3', '2.5.4', '2.5.5', '2.5.6', '2.5.7', '2.5.8', '2.5.9', '2.5.10', '2.5.11', '2.5.12', '2.5.13', '2.5.14', '2.6.0', '2.6.1', '2.6.2', '2.6.3', '2.6.4', '2.6.5', '2.6.6', '2.6.7', '2.6.8', '2.6.9', '2.6.10', '2.6.11', '2.6.12', '2.6.13', '2.6.14', '2.7.0', '2.7.1', '2.7.2', '2.7.3', '2.7.4', '2.7.5', '2.7.6', '2.7.7', '2.7.8', '2.7.9', '2.7.10', '2.7.11', '2.7.12', '2.7.13', '2.7.14', '2.8.0', '2.8.1', '2.8.2', '2.8.3', '2.8.4', '2.8.5', '2.8.6', '2.8.7', '2.8.8', '2.8.9', '2.8.10', '2.8.11', '2.8.12', '2.8.13', '2.8.14', '2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9', '2.9.10', '2.9.11', '2.9.12', '2.9.13', '2.9.14', '2.10.0', '2.10.1', '2.10.2', '2.10.3', '2.10.4', '2.10.5', '2.10.6', '2.10.7', '2.10.8', '2.10.9', '2.10.10', '2.10.11', '2.10.12', '2.10.13', '2.10.14', '2.11.0', '2.11.1', '2.11.2', '2.11.3', '2.11.4', '2.11.5', '2.11.6', '2.11.7', '2.11.8', '2.11.9', '2.11.10', '2.11.11', '2.11.12', '2.11.13', '2.11.14', '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5', '3.0.6', '3.0.7', '3.0.8', '3.0.9', '3.0.10', '3.0.11', '3.0.12', '3.0.13', '3.0.14', '3.0.15', '3.0.16', '3.0.17', '3.0.18', '3.0.19', '3.0.20', '3.0.21', '3.0.22', '3.0.23', '3.0.24', '3.0.25', '3.0.26', '3.0.27', '3.1.0', '3.1.1', '3.1.2', '3.1.3', '3.1.4', '3.1.5', '3.1.6', '3.2.0', '3.2.1', '3.2.2', '3.2.3', '3.2.4', '3.2.5', '3.2.6', '3.2.7', '3.2.8', '3.2.9', '3.3.0', '3.3.1', '3.3.2', '3.3.3', '3.3.4', '3.3.5', '3.3.6', '3.3.7', '3.3.8', '3.3.9', '3.3.10', '3.3.11', '3.3.12', '3.3.13', '3.3.14', '3.3.15', '3.3.16', '3.3.17', '3.3.18', '3.4.0', '3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6']
patched_pd_vers = ['3.4.7', '3.4.8', '3.4.9', '3.4.10', '4.0.0', '4.0.1', '4.1.0', '4.2.0', '4.2.1', '4.2.2', '4.2.3', '4.3.0', '4.3.1', '4.3.2', '4.4.0', '4.5.0', '4.6.0', '4.6.1', '4.7.0', '4.8.0']
vulnerable_neo4j_vers = ["4.4.2", "4.3.9", "4.2.13", "4.3.8", "4.4.1","4.2.12", "4.4.0", "4.3.7", "4.3.6", "4.3.5", "4.3.4", "4.2.11", "4.2.10", "4.3.3", "4.2.9", "4.3.2", "4.3.1", "4.2.8", "4.3.0", "4.2.7", "4.2.6", "4.2.5", "4.2.4", "4.2.3", "4.2.2", "4.2.1", "4.2.0"]
patched_neo4j_vers = ["4.4.3", "4.3.10", "4.2.14", "4.4.14", "4.3.21", "4.4.13", "4.3.20", "5.1.0", "4.3.19", "4.4.12", "4.3.18", "4.4.11", "4.2.19", "4.3.17", "4.4.10", "4.3.16", "4.4.9", "4.4.15", "4.2.18", "4.3.14", "4.4.8", "4.2.17", "4.3.13", "4.4.7", "4.4.6", "4.2.16", "4.3.12", "4.4.5", "4.3.11", "4.4.4", "4.2.15"]

patched_history = research_functions.get_patching_history(ip_to_history, service, patched_pd_vers)

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