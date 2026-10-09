// Title: Suspicious Run Key from Download
// ID: 9c5037d1-c568-49b3-88c7-9846a5bdc2be
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems)
// Date: 2019-10-01
// Tags: attack.privilege-escalation, attack.persistence, attack.t1547.001
// Description: Detects the suspicious RUN keys created by software located in Download or temporary Outlook/Internet Explorer directories
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_process_image_path contains "\\AppData\\Local\\Packages\\Microsoft.Outlook_" or action_process_image_path contains "\\AppData\\Local\\Microsoft\\Olk\\Attachments\\" or action_process_image_path contains "\\Downloads\\" or action_process_image_path contains "\\Temporary Internet Files\\Content.Outlook\\" or action_process_image_path contains "\\Local Settings\\Temporary Internet Files\\") and (TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" or TargetObject contains "\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" or TargetObject contains "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"))
