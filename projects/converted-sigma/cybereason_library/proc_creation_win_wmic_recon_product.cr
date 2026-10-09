// Title: Potential Product Reconnaissance Via Wmic.EXE
// ID: 15434e33-5027-4914-88d5-3d4145ec25a9
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali
// Date: 2023-02-14
// Tags: attack.execution, attack.t1047
// Description: Detects the execution of WMIC in order to get a list of firewall and antivirus products
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "Product") AND ((Image="*\\wmic.exe") OR (OriginalFileName == "wmic.exe"))) AND NOT ((((CommandLine contains " uninstall" OR CommandLine contains " install")) OR (CommandLine contains "csproduct"))))
