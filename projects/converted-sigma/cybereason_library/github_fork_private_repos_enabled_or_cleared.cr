// Title: Github Fork Private Repositories Setting Enabled/Cleared
// ID: 69b3bd1e-b38a-462f-9a23-fbdbf63d2294
// Status: test
// Level: medium
// Author: Romain Gaillard (@romain-gaillard)
// Date: 2024-07-29
// Tags: attack.persistence, attack.exfiltration, attack.t1020, attack.t1537
// Description: Detects when the policy allowing forks of private and internal repositories is changed (enabled or cleared).
// Converted by: Sigma Universal SIEM/EDR CLI

((action == "private_repository_forking.clear" OR action == "private_repository_forking.enable"))
