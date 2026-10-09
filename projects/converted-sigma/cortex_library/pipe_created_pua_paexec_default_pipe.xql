// Title: PUA - PAExec Default Named Pipe
// ID: f6451de4-df0a-41fa-8d72-b39f54a08db5
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-26
// Tags: attack.execution, attack.t1569.002
// Description: Detects PAExec default named pipe
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (PipeName startswith "\\PAExec")
