// Title: Security Software Discovery - Linux
// ID: c9d8b7fd-78e4-44fe-88f6-599135d46d60
// Status: test
// Level: low
// Author: Daniil Yugoslavskiy, oscd.community
// Date: 2020-10-19
// Tags: attack.discovery, attack.t1518.001
// Description: Detects usage of system utilities (only grep and egrep for now) to discover security software discovery
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/grep" OR Image="*/egrep") AND (CommandLine contains "nessusd" OR CommandLine contains "td-agent" OR CommandLine contains "packetbeat" OR CommandLine contains "filebeat" OR CommandLine contains "auditbeat" OR CommandLine contains "osqueryd" OR CommandLine contains "cbagentd" OR CommandLine contains "falcond"))
