# Title: Docker Container Discovery Via Dockerenv Listing
# ID: 11701de9-d5a5-44aa-8238-84252f131895
# Status: test
# Level: low
# Author: Seth Hanford
# Date: 2023-08-23
# Tags: attack.discovery, attack.t1082
# Description: Detects listing or file reading of ".dockerenv" which can be a sing of potential container discovery
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Docker Container Discovery Via Dockerenv Listing
def rule(event):
    # Detection Logic:
    # ((Image="*/cat" OR Image="*/dir" OR Image="*/find" OR Image="*/ls" OR Image="*/stat" OR Image="*/test" OR Image="*grep") AND CommandLine="*.dockerenv")
    return True

def title(event):
    return "Docker Container Discovery Via Dockerenv Listing"

