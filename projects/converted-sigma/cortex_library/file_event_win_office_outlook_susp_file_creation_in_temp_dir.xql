// Title: Suspicious File Created in Outlook Temporary Directory
// ID: fabb0e80-030c-4e3e-a104-d09676991ac3
// Status: experimental
// Level: high
// Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2025-07-22
// Tags: attack.initial-access, attack.t1566.001
// Description: Detects the creation of files with suspicious file extensions in the temporary directory that Outlook uses when opening attachments.
// This can be used to detect spear-phishing campaigns that use suspicious files as attachments, which may contain malicious code.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path endswith ".cpl" or action_file_path endswith ".hta" or action_file_path endswith ".iso" or action_file_path endswith ".rdp" or action_file_path endswith ".svg" or action_file_path endswith ".vba" or action_file_path endswith ".vbe" or action_file_path endswith ".vbs")) and (((action_file_path contains "\\AppData\\Local\\Packages\\Microsoft.Outlook_" or action_file_path contains "\\AppData\\Local\\Microsoft\\Olk\\Attachments\\")) or ((action_file_path contains "\\AppData\\Local\\Microsoft\\Windows\\" and action_file_path contains "\\Content.Outlook\\"))))
