// Title: WMI Backdoor Exchange Transport Agent
// ID: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
// Status: test
// Level: critical
// Author: Florian Roth (Nextron Systems)
// Date: 2019-10-11
// Tags: attack.privilege-escalation, attack.persistence, attack.t1546.003
// Description: Detects a WMI backdoor in Exchange Transport Agents via WMI event filters
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((actor_process_image_path endswith "\\EdgeTransport.exe") and not (((action_process_image_path = "C:\\Windows\\System32\\conhost.exe") or (action_process_image_path startswith "C:\\Program Files\\Microsoft\\Exchange Server\\" and action_process_image_path endswith "\\Bin\\OleConverter.exe"))))
