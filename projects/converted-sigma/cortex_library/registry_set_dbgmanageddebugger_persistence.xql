// Title: Potential Registry Persistence Attempt Via DbgManagedDebugger
// ID: 9827ae57-3802-418f-994b-d5ecf5cd974b
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-08-07
// Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.stealth, attack.t1574
// Description: Detects the addition of the "Debugger" value to the "DbgManagedDebugger" key in order to achieve persistence. Which will get invoked when an application crashes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((TargetObject endswith "\\Microsoft\\.NETFramework\\DbgManagedDebugger") and not ((Details = "\"C:\\Windows\\system32\\vsjitdebugger.exe\" PID %d APPDOM %d EXTEXT \"%s\" EVTHDL %d")))
