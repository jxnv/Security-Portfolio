// Title: Hardware Model Reconnaissance Via Wmic.EXE
// ID: 3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2023-02-14
// Tags: attack.execution, attack.t1047, car.2016-03-002
// Description: Detects the execution of WMIC with the "csproduct" which is used to obtain information such as hardware models and vendor information
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*csproduct*") AND ((Image="*\\wmic.exe") OR (OriginalFileName: "wmic.exe")))
