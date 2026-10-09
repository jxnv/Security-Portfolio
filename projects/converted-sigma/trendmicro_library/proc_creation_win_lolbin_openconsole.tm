// Title: Use of OpenConsole
// ID: 814c95cc-8192-4378-a70a-f1aafd877af1
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-06-16
// Tags: attack.execution, attack.t1059
// Description: Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting
// Converted by: Sigma Universal SIEM/EDR CLI

(((OriginalFileName: "OpenConsole.exe") OR (Image="*\\OpenConsole.exe")) AND NOT ((Image="C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal*")))
