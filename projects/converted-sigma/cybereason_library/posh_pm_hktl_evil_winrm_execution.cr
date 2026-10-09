// Title: HackTool - Evil-WinRm Execution - PowerShell Module
// ID: 9fe55ea2-4cd6-4491-8a54-dd6871651b51
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2024-02-25
// Tags: attack.lateral-movement
// Description: Detects the execution of Evil-WinRM via PowerShell Module logs by leveraging the hardcoded strings inside the utility.
// Converted by: Sigma Universal SIEM/EDR CLI

(((ContextInfo contains ":\\Windows\\System32\\wsmprovhost.exe" OR ContextInfo contains ":\\Windows\\SysWOW64\\wsmprovhost.exe")) AND (((Payload contains "value=\"(get-location).path" OR Payload contains "value=\"(get-item*).length" OR Payload contains "Invoke-Binary " OR Payload contains "Donut-Loader -process_id*-donutfile" OR Payload contains "Bypass-4MSI" OR Payload contains "IEX ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a))).replace('???','')")) OR ((Payload contains "$servicios = Get-ItemProperty \"registry::HKLM\\System\\CurrentControlSet\\Services\\\"" AND Payload contains "Where-Object {$_.imagepath -notmatch \"system\" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath")) OR ((Payload contains "$a +=  \\\"$($_.FullName.Replace('\\\\','/'))/\\\"}else{  $a += \\\"$($_.FullName.Replace('\\\\', '/'))\\\" }" AND Payload contains "$a=@();$"))))
