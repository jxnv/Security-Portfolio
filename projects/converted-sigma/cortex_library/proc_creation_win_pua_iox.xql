// Title: PUA- IOX Tunneling Tool Execution
// ID: d7654f02-e04b-4934-9838-65c46f187ebc
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-10-08
// Tags: attack.command-and-control, attack.t1090
// Description: Detects the use of IOX - a tool for port forwarding and intranet proxy purposes
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path endswith "\\iox.exe") or ((action_process_image_command_line contains ".exe fwd -l " or action_process_image_command_line contains ".exe fwd -r " or action_process_image_command_line contains ".exe proxy -l " or action_process_image_command_line contains ".exe proxy -r ")) or ((Hashes contains "MD5=9DB2D314DD3F704A02051EF5EA210993" or Hashes contains "SHA1=039130337E28A6623ECF9A0A3DA7D92C5964D8DD" or Hashes contains "SHA256=C6CF82919B809967D9D90EA73772A8AA1C1EB3BC59252D977500F64F1A0D6731")))
