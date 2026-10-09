// Title: HackTool - CACTUSTORCH Remote Thread Creation
// ID: 2e4e488a-6164-4811-9ea1-f960c7359c40
// Status: test
// Level: high
// Author: @SBousseaden (detection), Thomas Patzke (rule)
// Date: 2019-02-01
// Tags: attack.privilege-escalation, attack.execution, attack.stealth, attack.t1055.012, attack.t1059.005, attack.t1059.007, attack.t1218.005
// Description: Detects remote thread creation from CACTUSTORCH as described in references.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((SourceImage endswith "\\System32\\cscript.exe" or SourceImage endswith "\\System32\\wscript.exe" or SourceImage endswith "\\System32\\mshta.exe" or SourceImage endswith "\\winword.exe" or SourceImage endswith "\\excel.exe") and TargetImage contains "\\SysWOW64\\" and StartModule = null)
