// Title: Syslog Clearing or Removal Via System Utilities
// ID: 3fcc9b35-39e4-44c0-a2ad-9e82b6902b31
// Status: test
// Level: high
// Author: Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
// Date: 2021-10-15
// Tags: attack.defense-impairment, attack.t1685.006
// Description: Detects specific commands commonly used to remove or empty the syslog. Which is a technique often used by attacker as a method to hide their tracks
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "/var/log/syslog") AND ((Image="*/cp" AND CommandLine contains "/dev/null") OR (Image="*/ln" AND (CommandLine contains "/dev/null " AND CommandLine contains "/var/log/syslog") AND (CommandLine contains "-sf " OR CommandLine contains "-sfn " OR CommandLine contains "-sfT ")) OR (Image="*/mv") OR (Image="*/rm" AND (CommandLine contains " -r " OR CommandLine contains " -f " OR CommandLine contains " -rf " OR CommandLine contains "/var/log/syslog")) OR (Image="*/shred" AND CommandLine contains "-u ") OR (Image="*/truncate" AND (CommandLine contains "0 " AND CommandLine contains "/var/log/syslog") AND (CommandLine contains "-s " OR CommandLine contains "-c " OR CommandLine contains "--size")) OR (Image="*/unlink"))) OR (((CommandLine contains "journalctl --vacuum" OR CommandLine contains "journalctl --rotate")) OR ((CommandLine contains " > /var/log/syslog" OR CommandLine contains " >/var/log/syslog" OR CommandLine contains " >| /var/log/syslog" OR CommandLine contains ": > /var/log/syslog" OR CommandLine contains ":> /var/log/syslog" OR CommandLine contains ":>/var/log/syslog" OR CommandLine contains ">|/var/log/syslog"))))
