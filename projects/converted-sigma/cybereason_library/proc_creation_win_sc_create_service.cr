// Title: New Service Creation Using Sc.EXE
// ID: 85ff530b-261d-48c6-a441-facaa2e81e48
// Status: test
// Level: low
// Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
// Date: 2023-02-20
// Tags: attack.persistence, attack.privilege-escalation, attack.t1543.003
// Description: Detects the creation of a new service using the "sc.exe" utility.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\sc.exe" AND (CommandLine contains "create" AND CommandLine contains "binPath")) AND NOT (((ParentImage="C:\\Program Files (x86)\\Dropbox\\Client\\*" OR ParentImage="C:\\Program Files\\Dropbox\\Client\\*") AND ParentImage="*\\Dropbox.exe")))
