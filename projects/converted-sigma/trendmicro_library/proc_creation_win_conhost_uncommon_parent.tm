// Title: Conhost Spawned By Uncommon Parent Process
// ID: cbb9e3d1-2386-4e59-912e-62f1484f7a89
// Status: test
// Level: medium
// Author: Tim Rauch, Elastic (idea)
// Date: 2022-09-28
// Tags: attack.execution, attack.t1059
// Description: Detects when the Console Window Host (conhost.exe) process is spawned by an uncommon parent process, which could be indicative of potential code injection activity.
// Converted by: Sigma Universal SIEM/EDR CLI

((Image="*\\conhost.exe" AND (ParentImage="*\\explorer.exe" OR ParentImage="*\\lsass.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\services.exe" OR ParentImage="*\\smss.exe" OR ParentImage="*\\spoolsv.exe" OR ParentImage="*\\svchost.exe" OR ParentImage="*\\userinit.exe" OR ParentImage="*\\wininit.exe" OR ParentImage="*\\winlogon.exe")) AND NOT (((ParentCommandLine: "*-k apphost -s AppHostSvc*" OR ParentCommandLine: "*-k imgsvc*" OR ParentCommandLine: "*-k localService -p -s RemoteRegistry*" OR ParentCommandLine: "*-k LocalSystemNetworkRestricted -p -s NgcSvc*" OR ParentCommandLine: "*-k NetSvcs -p -s NcaSvc*" OR ParentCommandLine: "*-k netsvcs -p -s NetSetupSvc*" OR ParentCommandLine: "*-k netsvcs -p -s wlidsvc*" OR ParentCommandLine: "*-k NetworkService -p -s DoSvc*" OR ParentCommandLine: "*-k wsappx -p -s AppXSvc*" OR ParentCommandLine: "*-k wsappx -p -s ClipSVC*" OR ParentCommandLine: "*-k wusvcs -p -s WaaSMedicSvc*"))) AND NOT (((ParentCommandLine: "*C:\\Program Files (x86)\\Dropbox\\Client\\*" OR ParentCommandLine: "*C:\\Program Files\\Dropbox\\Client\\*"))))
