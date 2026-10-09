# Title: Network Sniffing - MacOs
# ID: adc9bcc4-c39c-4f6b-a711-1884017bf043
# Status: test
# Level: informational
# Author: Alejandro Ortuno, oscd.community
# Date: 2020-10-14
# Tags: attack.discovery, attack.credential-access, attack.t1040
# Description: Detects the usage of tooling to sniff network traffic.
# An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Network Sniffing - MacOs
def rule(event):
    # Detection Logic:
    # ((Image="*/tcpdump" OR Image="*/tshark"))
    return True

def title(event):
    return "Network Sniffing - MacOs"

