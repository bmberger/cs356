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

# Get Solr Admin data
def solr_query(version):
    return f"same_service(services.http.response.html_title=`Solr Admin` and services.http.response.body: `img/favicon.ico?_={version}`)"
vulnerable_solr_vers_queries = [solr_query(version) for version in get_history.vulnerable_solr_vers]
patched_solr_vers_queries = [solr_query(version) for version in get_history.patched_solr_vers]
#get_history.print_data(h, "Solr Admin", vulnerable_solr_vers_queries, patched_solr_vers_queries, "services.http.response.html_title=`Solr Admin`")

# Get Pagerduty data
def pd_query(version):
    return f"same_service(services.http.response.html_title: `Rundeck` and services.http.response.body:`https://docs.rundeck.com/{version}`)"
vulnerable_pd_vers_queries = [pd_query(version) for version in get_history.vulnerable_pd_vers]
patched_pd_vers_queries = [pd_query(version) for version in get_history.patched_pd_vers]
#get_history.print_data(h, "Rundeck", vulnerable_pd_vers_queries, patched_pd_vers_queries, "services.http.response.html_title: `Rundeck`")

# Get Neo4j data
def neo4j_query(version):
    return f"same_service(services.http.response.body:`\"neo4j_version\" : \"{version}\"`)"
vulnerable_neo4j_vers_queries = [neo4j_query(version) for version in get_history.vulnerable_neo4j_vers]
patched_neo4j_vers_queries = [neo4j_query(version) for version in get_history.patched_neo4j_vers]
get_history.print_data(h, "Neo4j", vulnerable_neo4j_vers_queries, patched_neo4j_vers_queries, "services.http.response.body: `neo4j`")