// Title: Suspicious Scheduled Task Creation via Masqueraded XML File
// ID: dd2a821e-3b07-4d3b-a9ac-929fe4c6ca0c
// Status: test
// Level: medium
// Author: Swachchhanda Shrawan Poudel, Elastic (idea)
// Date: 2023-04-20
// Tags: attack.privilege-escalation, attack.execution, attack.persistence, attack.stealth, attack.t1036.005, attack.t1053.005
// Description: Detects the creation of a scheduled task using the "-XML" flag with a file without the '.xml' extension. This behavior could be indicative of potential defense evasion attempt during persistence
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "*/create*" OR CommandLine: "*-create*")) AND ((CommandLine: "*/xml*" OR CommandLine: "*-xml*")) AND ((Image="*\\schtasks.exe") OR (OriginalFileName: "schtasks.exe"))) AND NOT (((CommandLine: "*.xml*") OR (ParentImage="*\\rundll32.exe" AND (ParentCommandLine: "*:\\WINDOWS\\Installer\\MSI*" AND ParentCommandLine: "*.tmp,zzzzInvokeManagedCustomActionOutOfProc*")) OR ((IntegrityLevel: "System" OR IntegrityLevel: "S-1-16-16384")))) AND NOT (((ParentImage="*:\\ProgramData\\OEM\\UpgradeTool\\CareCenter_*\\BUnzip\\Setup_msi.exe" OR ParentImage="*:\\Program Files\\Axis Communications\\AXIS Camera Station\\SetupActions.exe" OR ParentImage="*:\\Program Files\\Axis Communications\\AXIS Device Manager\\AdmSetupActions.exe" OR ParentImage="*:\\Program Files (x86)\\Zemana\\AntiMalware\\AntiMalware.exe" OR ParentImage="*:\\Program Files\\Dell\\SupportAssist\\pcdrcui.exe"))))
