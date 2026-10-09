// Title: FortiGate - Firewall Address Object Added
// ID: 5c8d7b41-3812-432f-a0bb-4cfb7c31827e
// Status: experimental
// Level: medium
// Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
// Date: 2025-11-01
// Tags: attack.defense-impairment, attack.t1686.002
// Description: Detects the addition of firewall address objects on a Fortinet FortiGate Firewall.
// Converted by: Sigma Universal SIEM/EDR CLI

(action: "Add" AND cfgpath: "firewall.address")
