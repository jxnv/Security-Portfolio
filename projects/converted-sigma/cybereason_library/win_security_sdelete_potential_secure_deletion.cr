// Title: Potential Secure Deletion with SDelete
// ID: 39a80702-d7ca-4a83-b776-525b1f86a36d
// Status: test
// Level: medium
// Author: Thomas Patzke
// Date: 2017-06-14
// Tags: attack.impact, attack.stealth, attack.defense-impairment, attack.t1070.004, attack.t1027.005, attack.t1485, attack.t1553.002, attack.s0195
// Description: Detects files that have extensions commonly seen while SDelete is used to wipe files.
// Converted by: Sigma Universal SIEM/EDR CLI

((EventID == "4656" OR EventID == "4663" OR EventID == "4658") AND (ObjectName="*.AAA" OR ObjectName="*.ZZZ"))
