// Title: Suspicious PsExec Execution
// ID: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
// Status: test
// Level: high
// Author: Samir Bousseaden
// Date: 2019-04-03
// Tags: attack.lateral-movement, attack.t1021.002
// Description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((EventID = 5145 and ShareName = "\\\\\\\\\\*\\\\IPC$" and (RelativeTargetName endswith "-stdin" or RelativeTargetName endswith "-stdout" or RelativeTargetName endswith "-stderr")) and not ((RelativeTargetName startswith "PSEXESVC")))
