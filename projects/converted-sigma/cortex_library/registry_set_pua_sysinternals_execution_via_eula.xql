// Title: PUA - Sysinternal Tool Execution - Registry
// ID: 25ffa65d-76d8-4da5-a832-3f2b0136e133
// Status: test
// Level: low
// Author: Markus Neis
// Date: 2017-08-28
// Tags: attack.resource-development, attack.t1588.002
// Description: Detects the execution of a Sysinternals Tool via the creation of the "accepteula" registry key
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (TargetObject endswith "\\EulaAccepted")
