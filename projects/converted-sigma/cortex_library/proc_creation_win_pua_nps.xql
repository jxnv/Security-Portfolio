// Title: PUA - NPS Tunneling Tool Execution
// ID: 68d37776-61db-42f5-bf54-27e87072d17e
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-10-08
// Tags: attack.command-and-control, attack.t1090
// Description: Detects the use of NPS, a port forwarding and intranet penetration proxy server
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_process_image_command_line contains " -server=" and action_process_image_command_line contains " -vkey=" and action_process_image_command_line contains " -password=")) or (action_process_image_command_line contains " -config=npc") or ((Hashes contains "MD5=AE8ACF66BFE3A44148964048B826D005" or Hashes contains "SHA1=CEA49E9B9B67F3A13AD0BE1C2655293EA3C18181" or Hashes contains "SHA256=5A456283392FFCEEEACA3D3426C306EB470304637520D72FED1CC1FEBBBD6856")) or (action_process_image_path endswith "\\npc.exe"))
