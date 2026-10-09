// Title: Potential Persistence Via App Paths Default Property
// ID: 707e097c-e20f-4f67-8807-1f72ff4500d6
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-08-10
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.012
// Description: Detects changes to the "Default" property for keys located in the \Software\Microsoft\Windows\CurrentVersion\App Paths\ registry. Which might be used as a method of persistence
// The entries found under App Paths are used primarily for the following purposes.
// First, to map an application's executable file name to that file's fully qualified path.
// Second, to prepend information to the PATH environment variable on a per-application, per-process basis.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject contains "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths" and (TargetObject endswith "(Default)" or TargetObject endswith "Path") and (Details contains "\\Users\\Public" or Details contains "\\AppData\\Local\\Temp\\" or Details contains "\\Windows\\Temp\\" or Details contains "\\Desktop\\" or Details contains "\\Downloads\\" or Details contains "%temp%" or Details contains "%tmp%" or Details contains "iex" or Details contains "Invoke-" or Details contains "rundll32" or Details contains "regsvr32" or Details contains "mshta" or Details contains "cscript" or Details contains "wscript" or Details contains ".bat" or Details contains ".hta" or Details contains ".dll" or Details contains ".ps1"))
