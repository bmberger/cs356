from censys.search import SearchClient
from censys.search import CensysHosts
import heapq
import csv
import json
import datetime
from os.path import exists
import get_history

# Main
h = CensysHosts()
date = datetime.datetime.now()
print(f'"current" date and time being used is {date}')
datetimes = [datetime.date(2021, 12, 6), datetime.date(2022, 1, 6), datetime.date(2022, 2, 6), datetime.date(2022, 3, 6), datetime.date(2022, 4, 6), datetime.date(2022, 5, 6), datetime.date(2022, 6, 6), datetime.date(2022, 7, 6), datetime.date(2022, 8, 6), datetime.date(2022, 9, 6), datetime.date(2022, 10, 6), datetime.date(2022, 11, 6), datetime.date(2022, 12, 9)]

# Get Solr Admin data
def solr_query(version):
    return f"same_service(services.http.response.html_title=`Solr Admin` and services.http.response.body: `img/favicon.ico?_={version}`)"
vulnerable_solr_vers_queries = [solr_query(version) for version in get_history.vulnerable_solr_vers]
patched_solr_vers_queries = [solr_query(version) for version in get_history.patched_solr_vers]
#get_history.print_data(h, "Solr Admin", vulnerable_solr_vers_queries, patched_solr_vers_queries, "services.http.response.html_title=`Solr Admin`", datetimes, "_history.json", get_history.vulnerable_solr_vers, get_history.patched_solr_vers)
get_history.print_data(h, "Solr Admin", vulnerable_solr_vers_queries, patched_solr_vers_queries, "services.http.response.html_title=`Solr Admin`", [date], "_curresp.json", get_history.vulnerable_solr_vers, get_history.patched_solr_vers)
print("solr is done")

# Get Pagerduty data
def pd_query(version):
    return f"same_service(services.http.response.html_title: `Rundeck` and services.http.response.body:`https://docs.rundeck.com/{version}`)"
vulnerable_pd_vers_queries = [pd_query(version) for version in get_history.vulnerable_pd_vers]
patched_pd_vers_queries = [pd_query(version) for version in get_history.patched_pd_vers]
# get_history.print_data(h, "Rundeck", vulnerable_pd_vers_queries, patched_pd_vers_queries, "services.http.response.html_title: `Rundeck`", datetimes, "_history.json", get_history.vulnerable_pd_vers, get_history.patched_pd_vers)
get_history.print_data(h, "Rundeck", vulnerable_pd_vers_queries, patched_pd_vers_queries, "services.http.response.html_title: `Rundeck`", [date], "_curresp.json", get_history.vulnerable_pd_vers, get_history.patched_pd_vers)
print("rundeck is done")

# Get Neo4j data
def neo4j_query(version):
    return f"same_service(services.http.response.body:`\"neo4j_version\" : \"{version}\"`)"
vulnerable_neo4j_vers_queries = [neo4j_query(version) for version in get_history.vulnerable_neo4j_vers]
patched_neo4j_vers_queries = [neo4j_query(version) for version in get_history.patched_neo4j_vers]
#get_history.print_data(h, "Neo4j", vulnerable_neo4j_vers_queries, patched_neo4j_vers_queries, "services.http.response.body: `neo4j`", datetimes, "_history.json", get_history.vulnerable_neo4j_vers, get_history.patched_neo4j_vers)
get_history.print_data(h, "Neo4j", vulnerable_neo4j_vers_queries, patched_neo4j_vers_queries, "services.http.response.body: `neo4j`", [date], "_curresp.json", get_history.vulnerable_neo4j_vers, get_history.patched_neo4j_vers)
print("neo4j is done")