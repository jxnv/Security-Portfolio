// Title: Potential Suspicious PowerShell Module File Created
// ID: e8a52bbd-bced-459f-bd93-64db45ce7657
// Status: test
// Level: medium
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2023-05-09
// Tags: attack.persistence
// Description: Detects the creation of a new PowerShell module in the first folder of the module directory structure "\WindowsPowerShell\Modules\malware\malware.psm1". This is somewhat an uncommon practice as legitimate modules often includes a version folder.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((action_file_path endswith "\\\\WindowsPowerShell\\\\Modules\\\\*\\.ps" or action_file_path endswith "\\\\WindowsPowerShell\\\\Modules\\\\*\\.dll"))
