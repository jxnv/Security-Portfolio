// Title: HackTool - Pypykatz Credentials Dumping Activity
// ID: a29808fd-ef50-49ff-9c7a-59a9b040b404
// Status: test
// Level: high
// Author: frack113
// Date: 2022-01-05
// Tags: attack.credential-access, attack.t1003.002
// Description: Detects the usage of "pypykatz" to obtain stored credentials. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database through Windows registry where the SAM database is stored
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\pypykatz.exe" OR Image="*\\python.exe") AND (CommandLine contains "live" AND CommandLine contains "registry"))
