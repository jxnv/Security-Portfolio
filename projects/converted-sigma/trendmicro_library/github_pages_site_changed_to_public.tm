// Title: GitHub Repository Pages Site Changed to Public
// ID: 0c46d4f4-a2bf-4104-9597-8d653fc2bb55
// Status: experimental
// Level: low
// Author: Ivan Saakov
// Date: 2025-10-18
// Tags: attack.collection, attack.exfiltration, attack.t1567.001
// Description: Detects when a GitHub Pages site of a repository is made public. This usually is part of a publishing process but could indicate or lead to potential unauthorized exposure of sensitive information or code.
// Converted by: Sigma Universal SIEM/EDR CLI

(action: "repo.pages_public")
