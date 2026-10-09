// Title: Windows Shell/Scripting Application File Write to Suspicious Folder
// ID: 1277f594-a7d1-4f28-a2d3-73af5cbeab43
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-11-20
// Tags: attack.execution, attack.t1059
// Description: Detects Windows shells and scripting applications that write files to suspicious folders
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\bash.exe" OR Image="*\\cmd.exe" OR Image="*\\cscript.exe" OR Image="*\\msbuild.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\sh.exe" OR Image="*\\wscript.exe") AND (TargetFilename="C:\\PerfLogs\\*" OR TargetFilename="C:\\Users\\Public\\*")) OR ((Image="*\\certutil.exe" OR Image="*\\forfiles.exe" OR Image="*\\mshta.exe" OR Image="*\\schtasks.exe" OR Image="*\\scriptrunner.exe" OR Image="*\\wmic.exe") AND (TargetFilename contains "C:\\PerfLogs\\" OR TargetFilename contains "C:\\Users\\Public\\" OR TargetFilename contains "C:\\Windows\\Temp\\")))
