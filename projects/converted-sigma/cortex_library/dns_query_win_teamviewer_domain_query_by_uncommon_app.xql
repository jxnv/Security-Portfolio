// Title: TeamViewer Domain Query By Non-TeamViewer Application
// ID: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2022-01-30
// Tags: attack.command-and-control, attack.t1219.002
// Description: Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((QueryName = "taf.teamviewer.com" or QueryName = "udp.ping.teamviewer.com")) and not ((action_process_image_path contains "TeamViewer")))
