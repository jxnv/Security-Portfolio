// Title: Tor Client/Browser Execution
// ID: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
// Status: test
// Level: high
// Author: frack113
// Date: 2022-02-20
// Tags: attack.command-and-control, attack.t1090.003
// Description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((Description = "Tor Browser") or (Product = "Tor Browser") or ((action_process_image_path endswith "\\tor.exe" or action_process_image_path endswith "\\Tor Browser\\Browser\\firefox.exe")))
