// Title: New Netsh Helper DLL Registered From A Suspicious Location
// ID: e7b18879-676e-4a0e-ae18-27039185a8e7
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-11-28
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.007
// Description: Detects changes to the Netsh registry key to add a new DLL value that is located on a suspicious location. This change might be an indication of a potential persistence attempt by adding a malicious Netsh helper
// Converted by: Sigma Universal SIEM/EDR CLI

((TargetObject: "*\\SOFTWARE\\Microsoft\\NetSh*") AND (((Details: "*:\\Perflogs\\*" OR Details: "*:\\Users\\Public\\*" OR Details: "*:\\Windows\\Temp\\*" OR Details: "*\\AppData\\Local\\Temp\\*" OR Details: "*\\Temporary Internet*")) OR (((Details: "*:\\Users\\*" AND Details: "*\\Favorites\\*")) OR ((Details: "*:\\Users\\*" AND Details: "*\\Favourites\\*")) OR ((Details: "*:\\Users\\*" AND Details: "*\\Contacts\\*")) OR ((Details: "*:\\Users\\*" AND Details: "*\\Pictures\\*")))))
