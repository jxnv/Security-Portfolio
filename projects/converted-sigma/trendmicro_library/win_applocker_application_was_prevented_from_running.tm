// Title: AppLocker Prevented Application or Script from Running
// ID: 401e5d00-b944-11ea-8f9a-00163ecd60ae
// Status: test
// Level: medium
// Author: Pushkarev Dmitry
// Date: 2020-06-28
// Tags: attack.execution, attack.t1204.002, attack.t1059.001, attack.t1059.003, attack.t1059.005, attack.t1059.006, attack.t1059.007
// Description: Detects when AppLocker prevents the execution of an Application, DLL, Script, MSI, or Packaged-App from running.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID: "8004" OR EventID: "8007" OR EventID: "8022" OR EventID: "8025"))
