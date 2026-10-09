// Title: PUA - Fast Reverse Proxy (FRP) Execution
// ID: 32410e29-5f94-4568-b6a3-d91a8adad863
// Status: test
// Level: high
// Author: frack113, Florian Roth
// Date: 2022-09-02
// Tags: attack.command-and-control, attack.t1090
// Description: Detects the use of Fast Reverse Proxy. frp is a fast reverse proxy to help you expose a local server behind a NAT or firewall to the Internet.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_command_line contains "\\frpc.ini") or ((Hashes contains "MD5=7D9C233B8C9E3F0EA290D2B84593C842" or Hashes contains "SHA1=06DDC9280E1F1810677935A2477012960905942F" or Hashes contains "SHA256=57B0936B8D336D8E981C169466A15A5FD21A7D5A2C7DAF62D5E142EE860E387C")) or ((action_process_image_path endswith "\\frpc.exe" or action_process_image_path endswith "\\frps.exe")))
