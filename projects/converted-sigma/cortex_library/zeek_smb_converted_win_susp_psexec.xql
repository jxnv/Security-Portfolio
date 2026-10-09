// Title: Suspicious PsExec Execution - Zeek
// ID: f1b3a22a-45e6-4004-afb5-4291f9c21166
// Status: test
// Level: high
// Author: Samir Bousseaden, @neu5ron, Tim Shelton
// Date: 2020-04-02
// Tags: attack.lateral-movement, attack.t1021.002
// Description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((path contains "\\\\" and path contains "\\IPC$") and (name endswith "-stdin" or name endswith "-stdout" or name endswith "-stderr")) and not ((name startswith "PSEXESVC")))
