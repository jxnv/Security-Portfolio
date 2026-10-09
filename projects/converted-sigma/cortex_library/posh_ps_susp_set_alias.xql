// Title: Potential PowerShell Obfuscation Using Alias Cmdlets
// ID: 96cd126d-f970-49c4-848a-da3a09f55c55
// Status: test
// Level: low
// Author: frack113
// Date: 2023-01-08
// Tags: attack.execution, attack.stealth, attack.t1027, attack.t1059.001
// Description: Detects Set-Alias or New-Alias cmdlet usage. Which can be use as a mean to obfuscate PowerShell scripts
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ScriptBlockText contains "Set-Alias " or ScriptBlockText contains "New-Alias ")) and not (((ScriptBlockText = "Set-Alias -Name ncms -Value New-CimSession -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name gcls -Value Get-CimClass -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name ncso -Value New-CimSessionOption -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name gcms -Value Get-CimSession -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name rcms -Value Remove-cimSession -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name rcie -Value Register-CimIndicationEvent -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name gcai -Value Get-CimAssociatedInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name gcim -Value Get-CimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name scim -Value Set-CimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name ncim -Value New-CimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name ncim -Value New-CimInstance  -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name rcim -Value Remove-cimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue" or ScriptBlockText = "Set-Alias -Name icim -Value Invoke-CimMethod -Option ReadOnly, AllScope -ErrorAction SilentlyContinue"))))
