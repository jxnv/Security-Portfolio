// Title: Possible Coin Miner CPU Priority Param
// ID: 071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2021-10-09
// Tags: attack.privilege-escalation, attack.t1068
// Description: Detects command line parameter very often used with coin miners
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((a1 startswith "--cpu-priority") or (a2 startswith "--cpu-priority") or (a3 startswith "--cpu-priority") or (a4 startswith "--cpu-priority") or (a5 startswith "--cpu-priority") or (a6 startswith "--cpu-priority") or (a7 startswith "--cpu-priority"))
