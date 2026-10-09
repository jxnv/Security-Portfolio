// Title: Potential File Extension Spoofing Using Right-to-Left Override
// ID: 979baf41-ca44-4540-9d0c-4fcef3b5a3a4
// Status: test
// Level: high
// Author: Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2024-11-17
// Tags: attack.execution, attack.stealth, attack.t1036.002
// Description: Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "3pm." or action_file_path contains "4pm." or action_file_path contains "cod." or action_file_path contains "fdp." or action_file_path contains "ftr." or action_file_path contains "gepj." or action_file_path contains "gnp." or action_file_path contains "gpj." or action_file_path contains "ism." or action_file_path contains "lmth." or action_file_path contains "nls." or action_file_path contains "piz." or action_file_path contains "slx." or action_file_path contains "tdo." or action_file_path contains "vsc." or action_file_path contains "vwm." or action_file_path contains "xcod." or action_file_path contains "xslx." or action_file_path contains "xtpp.")) and ((action_file_path contains "\\u202e" or action_file_path contains "[U+202E]" or action_file_path contains "‮")))
