// Title: RDP to HTTP or HTTPS Target Ports
// ID: b1e5da3b-ca8e-4adf-915c-9921f3d85481
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-04-29
// Tags: attack.command-and-control, attack.t1572, attack.lateral-movement, attack.t1021.001, car.2013-07-002
// Description: Detects svchost hosting RDP termsvcs communicating to target systems on TCP port 80 or 443
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (action_process_image_path endswith "\\svchost.exe" and Initiated = "true" and action_local_port = 3389 and (action_remote_port = 80 or action_remote_port = 443))
