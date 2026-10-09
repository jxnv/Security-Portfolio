// Title: Linux Package Uninstall
// ID: 95d61234-7f56-465c-6f2d-b562c6fedbc4
// Status: test
// Level: low
// Author: Tuan Le (NCSGroup), Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-03-09
// Tags: attack.stealth, attack.t1070
// Description: Detects linux package removal using builtin tools such as "yum", "apt", "apt-get" or "dpkg".
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*/apt" OR Image="*/apt-get") AND (CommandLine contains "remove" OR CommandLine contains "purge")) OR (Image="*/dpkg" AND (CommandLine contains "--remove " OR CommandLine contains " -r ")) OR (Image="*/rpm" AND CommandLine contains " -e ") OR (Image="*/yum" AND (CommandLine contains "erase" OR CommandLine contains "remove")))
