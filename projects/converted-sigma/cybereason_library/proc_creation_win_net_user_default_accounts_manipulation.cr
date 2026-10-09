// Title: Suspicious Manipulation Of Default Accounts Via Net.EXE
// ID: 5b768e71-86f2-4879-b448-81061cbae951
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-09-01
// Tags: attack.collection, attack.t1560.001
// Description: Detects suspicious manipulations of default accounts such as 'administrator' and 'guest'. For example 'enable' or 'disable' accounts or change the password...etc
// Converted by: Sigma Universal SIEM/EDR CLI

(((((Image="*\\net.exe" OR Image="*\\net1.exe")) OR ((OriginalFileName == "net.exe" OR OriginalFileName == "net1.exe"))) AND (CommandLine contains " user ") AND ((CommandLine contains " Järjestelmänvalvoja " OR CommandLine contains " Rendszergazda " OR CommandLine contains " Администратор " OR CommandLine contains " Administrateur " OR CommandLine contains " Administrador " OR CommandLine contains " Administratör " OR CommandLine contains " Administrator " OR CommandLine contains " guest " OR CommandLine contains " DefaultAccount " OR CommandLine contains " \"Järjestelmänvalvoja\" " OR CommandLine contains " \"Rendszergazda\" " OR CommandLine contains " \"Администратор\" " OR CommandLine contains " \"Administrateur\" " OR CommandLine contains " \"Administrador\" " OR CommandLine contains " \"Administratör\" " OR CommandLine contains " \"Administrator\" " OR CommandLine contains " \"guest\" " OR CommandLine contains " \"DefaultAccount\" " OR CommandLine contains " 'Järjestelmänvalvoja' " OR CommandLine contains " 'Rendszergazda' " OR CommandLine contains " 'Администратор' " OR CommandLine contains " 'Administrateur' " OR CommandLine contains " 'Administrador' " OR CommandLine contains " 'Administratör' " OR CommandLine contains " 'Administrator' " OR CommandLine contains " 'guest' " OR CommandLine contains " 'DefaultAccount' "))) AND NOT (((CommandLine contains "guest" AND CommandLine contains "/active no"))))
