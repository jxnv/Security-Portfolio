// Title: Arbitrary File Download Via MSEDGE_PROXY.EXE
// ID: e84d89c4-f544-41ca-a6af-4b92fd38b023
// Status: test
// Level: medium
// Author: Swachchhanda Shrawan Poudel
// Date: 2023-11-09
// Tags: attack.execution, attack.stealth, attack.t1218
// Description: Detects usage of "msedge_proxy.exe" to download arbitrary files
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*http://*" OR CommandLine: "*https://*")) AND ((Image="*\\msedge_proxy.exe") OR (OriginalFileName: "msedge_proxy.exe")))
