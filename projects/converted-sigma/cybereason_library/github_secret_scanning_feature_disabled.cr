// Title: Github Secret Scanning Feature Disabled
// ID: 3883d9a0-fd0f-440f-afbb-445a2a799bb8
// Status: test
// Level: high
// Author: Muhammad Faisal (@faisalusuf)
// Date: 2024-03-07
// Tags: attack.defense-impairment, attack.t1685
// Description: Detects if the secret scanning feature is disabled for an enterprise or repository.
// Converted by: Sigma Universal SIEM/EDR CLI

((action == "business_secret_scanning.disable" OR action == "business_secret_scanning.disabled_for_new_repos" OR action == "repository_secret_scanning.disable" OR action == "secret_scanning_new_repos.disable" OR action == "secret_scanning.disable"))
