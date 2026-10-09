// Title: Local Groups Discovery - MacOs
// ID: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
// Status: test
// Level: informational
// Author: Ömer Günal, Alejandro Ortuno, oscd.community
// Date: 2020-10-11
// Tags: attack.discovery, attack.t1069.001
// Description: Detects enumeration of local system groups
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*/dscacheutil" AND (CommandLine contains "-q" AND CommandLine contains "group")) OR (Image="*/cat" AND CommandLine contains "/etc/group") OR (Image="*/dscl" AND (CommandLine contains "-list" AND CommandLine contains "/groups")))
