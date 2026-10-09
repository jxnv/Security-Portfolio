# Title: Flush Iptables Ufw Chain
# ID: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
# Status: test
# Level: medium
# Author: Joseliyo Sanchez, @Joseliyo_Jstnk
# Date: 2023-01-18
# Tags: attack.defense-impairment, attack.t1686
# Description: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
# Converted by: Sigma Universal SIEM/EDR CLI

# Panther Detection Rule: Flush Iptables Ufw Chain
def rule(event):
    # Detection Logic:
    # (((Image="*/iptables" OR Image="*/xtables-legacy-multi" OR Image="*/iptables-legacy-multi" OR Image="*/ip6tables" OR Image="*/ip6tables-legacy-multi")) AND ((CommandLine="*-F*" OR CommandLine="*-Z*" OR CommandLine="*-X*")) AND ((CommandLine="*ufw-logging-deny*" OR CommandLine="*ufw-logging-allow*" OR CommandLine="*ufw6-logging-deny*" OR CommandLine="*ufw6-logging-allow*")))
    return True

def title(event):
    return "Flush Iptables Ufw Chain"

