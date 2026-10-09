// Title: Impacket PsExec Execution
// ID: 32d56ea1-417f-44ff-822b-882873f5f43b
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2020-12-14
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects execution of Impacket's psexec.py.
// Converted by: Sigma Universal SIEM/EDR CLI

(EventID: "5145" AND ShareName: "\\\\\\\\\\*\\\\IPC$" AND (RelativeTargetName: "*RemCom_stdin*" OR RelativeTargetName: "*RemCom_stdout*" OR RelativeTargetName: "*RemCom_stderr*"))
