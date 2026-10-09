// Title: Potential CommandLine Path Traversal Via Cmd.EXE
// ID: 087790e3-3287-436c-bccf-cbd0184a7db1
// Status: test
// Level: high
// Author: xknow @xknow_infosec, Tim Shelton
// Date: 2020-06-11
// Tags: attack.execution, attack.t1059.003
// Description: Detects potential path traversal attempt via cmd.exe. Could indicate possible command/argument confusion/hijacking
// Converted by: Sigma Universal SIEM/EDR CLI

(((((ParentCommandLine: "*/c*" OR ParentCommandLine: "*/k*" OR ParentCommandLine: "*/r*")) OR ((CommandLine: "*/c*" OR CommandLine: "*/k*" OR CommandLine: "*/r*"))) AND ((ParentImage="*\\cmd.exe") OR (Image="*\\cmd.exe") OR (OriginalFileName: "cmd.exe")) AND ((ParentCommandLine: "/../../") OR (CommandLine: "*/../../*"))) AND NOT ((CommandLine: "*\\Tasktop\\keycloak\\bin\\/../../jre\\bin\\java*")))
