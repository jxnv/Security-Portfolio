// Title: Local Groups Discovery - Linux
// ID: 676381a6-15ca-4d73-a9c8-6a22e970b90d
// Status: test
// Level: low
// Author: Ömer Günal, Alejandro Ortuno, oscd.community
// Date: 2020-10-11
// Tags: attack.discovery, attack.t1069.001
// Description: Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/groups") OR ((Image="*/cat" OR Image="*/ed" OR Image="*/head" OR Image="*/less" OR Image="*/more" OR Image="*/nano" OR Image="*/tail" OR Image="*/vi" OR Image="*/vim") AND CommandLine contains "/etc/group"))
