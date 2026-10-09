// Title: Shell32 DLL Execution in Suspicious Directory
// ID: 32b96012-7892-429e-b26c-ac2bf46066ff
// Status: test
// Level: high
// Author: Christian Burkard (Nextron Systems)
// Date: 2021-11-24
// Tags: attack.execution, attack.stealth, attack.t1218.011
// Description: Detects shell32.dll executing a DLL in a suspicious directory
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "shell32.dll" AND CommandLine contains "Control_RunDLL") AND (CommandLine contains "%AppData%" OR CommandLine contains "%LocalAppData%" OR CommandLine contains "%Temp%" OR CommandLine contains "%tmp%" OR CommandLine contains "\\AppData\\" OR CommandLine contains "\\Temp\\" OR CommandLine contains "\\Users\\Public\\")) AND ((Image="*\\rundll32.exe") OR (OriginalFileName == "RUNDLL32.EXE")))
