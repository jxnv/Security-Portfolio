// Title: PUA - 3Proxy Execution
// ID: f38a82d2-fba3-4781-b549-525efbec8506
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-09-13
// Tags: attack.command-and-control, attack.t1572
// Description: Detects the use of 3proxy, a tiny free proxy server
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\3proxy.exe") or (action_process_image_command_line contains ".exe -i127.0.0.1 -p") or (Description = "3proxy - tiny proxy server"))
