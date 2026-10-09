# Title: Rclone Activity via Proxy
# ID: 2c03648b-e081-41a5-b9fb-7d854a915091
# Status: test
# Level: medium
# Author: Janantha Marasinghe
# Date: 2022-10-18
# Tags: attack.exfiltration, attack.t1567.002
# Description: Detects the use of rclone, a command-line program to manage files on cloud storage, via its default user-agent string
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Rclone Activity via Proxy
def rule(event):
    # Detection Logic:
    # (c-useragent="rclone/v*")
    return True

def title(event):
    return "Rclone Activity via Proxy"

