// Title: Flush Iptables Ufw Chain
// ID: 3be619f4-d9ec-4ea8-a173-18fdd01996ab
// Status: test
// Level: medium
// Author: Joseliyo Sanchez, @Joseliyo_Jstnk
// Date: 2023-01-18
// Tags: attack.defense-impairment, attack.t1686
// Description: Detect use of iptables to flush all firewall rules, tables and chains and allow all network traffic
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*/iptables" OR Image="*/xtables-legacy-multi" OR Image="*/iptables-legacy-multi" OR Image="*/ip6tables" OR Image="*/ip6tables-legacy-multi")) AND ((CommandLine contains "-F" OR CommandLine contains "-Z" OR CommandLine contains "-X")) AND ((CommandLine contains "ufw-logging-deny" OR CommandLine contains "ufw-logging-allow" OR CommandLine contains "ufw6-logging-deny" OR CommandLine contains "ufw6-logging-allow")))
