// Title: Impacket PsExec Execution
// ID: 32d56ea1-417f-44ff-822b-882873f5f43b
// Status: test
// Level: high
// Author: Bhabesh Raj
// Date: 2020-12-14
// Tags: attack.lateral-movement, attack.t1021.002
// Description: Detects execution of Impacket's psexec.py.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (EventID = 5145 and ShareName = "\\\\\\\\\\*\\\\IPC$" and (RelativeTargetName contains "RemCom_stdin" or RelativeTargetName contains "RemCom_stdout" or RelativeTargetName contains "RemCom_stderr"))
