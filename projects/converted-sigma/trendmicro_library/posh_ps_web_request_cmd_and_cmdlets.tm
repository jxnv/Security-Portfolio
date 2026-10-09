// Title: Usage Of Web Request Commands And Cmdlets - ScriptBlock
// ID: 1139d2e2-84b1-4226-b445-354492eba8ba
// Status: test
// Level: medium
// Author: James Pemberton / @4A616D6573
// Date: 2019-10-24
// Tags: attack.execution, attack.t1059.001
// Description: Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via PowerShell scriptblock logs
// Converted by: Sigma Universal SIEM/EDR CLI

(((ScriptBlockText: "*[System.Net.WebRequest]::create*" OR ScriptBlockText: "*curl *" OR ScriptBlockText: "*Invoke-RestMethod*" OR ScriptBlockText: "*Invoke-WebRequest*" OR ScriptBlockText: "* irm *" OR ScriptBlockText: "*iwr *" OR ScriptBlockText: "*Resume-BitsTransfer*" OR ScriptBlockText: "*Start-BitsTransfer*" OR ScriptBlockText: "*wget *" OR ScriptBlockText: "*WinHttp.WinHttpRequest*")) AND NOT ((Path="C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\*")))
