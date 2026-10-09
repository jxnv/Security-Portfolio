// Title: New Capture Session Launched Via DXCap.EXE
// ID: 60f16a96-db70-42eb-8f76-16763e333590
// Status: test
// Level: medium
// Author: Beyu Denis, oscd.community, Nasreddine Bencherchali (Nextron Systems)
// Date: 2019-10-26
// Tags: attack.stealth, attack.t1218
// Description: Detects the execution of "DXCap.EXE" with the "-c" flag, which allows a user to launch any arbitrary binary or windows package through DXCap itself. This can be abused to potentially bypass application whitelisting.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine contains " -c ") AND ((Image="*\\DXCap.exe") OR (OriginalFileName == "DXCap.exe")))
