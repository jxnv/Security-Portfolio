// Title: Local Accounts Discovery
// ID: 502b42de-4306-40b4-9596-6f590c81f073
// Status: test
// Level: low
// Author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
// Date: 2019-10-21
// Tags: attack.discovery, attack.t1033, attack.t1087.001
// Description: Local accounts, System Owner/User discovery using operating systems utilities
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\cmd.exe" AND (CommandLine contains " /c" AND CommandLine contains "dir " AND CommandLine contains "\\Users\\")) AND NOT ((CommandLine contains " rmdir "))) OR (((Image="*\\net.exe" OR Image="*\\net1.exe") AND CommandLine contains "user") AND NOT (((CommandLine contains "/domain" OR CommandLine contains "/add" OR CommandLine contains "/delete" OR CommandLine contains "/active" OR CommandLine contains "/expires" OR CommandLine contains "/passwordreq" OR CommandLine contains "/scriptpath" OR CommandLine contains "/times" OR CommandLine contains "/workstations")))) OR ((Image="*\\cmdkey.exe" AND CommandLine contains " /l") OR (((Image="*\\whoami.exe" OR Image="*\\quser.exe" OR Image="*\\qwinsta.exe")) OR ((OriginalFileName == "whoami.exe" OR OriginalFileName == "quser.exe" OR OriginalFileName == "qwinsta.exe"))) OR (Image="*\\wmic.exe" AND (CommandLine contains "useraccount" AND CommandLine contains "get"))))
