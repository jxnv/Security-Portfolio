// Title: Suspicious MSExchangeMailboxReplication ASPX Write
// ID: 7280c9f3-a5af-45d0-916a-bc01cb4151c9
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-02-25
// Tags: attack.initial-access, attack.t1190, attack.persistence, attack.t1505.003
// Description: Detects suspicious activity in which the MSExchangeMailboxReplication process writes .asp and .apsx files to disk, which could be a sign of ProxyShell exploitation
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\MSExchangeMailboxReplication.exe" and (action_file_path endswith ".aspx" or action_file_path endswith ".asp"))
