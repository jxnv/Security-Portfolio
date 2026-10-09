// Title: FortiGate - New Local User Created
// ID: ddbbe845-1d74-43a8-8231-2156d180234d
// Status: experimental
// Level: medium
// Author: Marco Pedrinazzi (@pedrinazziM) (InTheCyber)
// Date: 2025-11-01
// Tags: attack.persistence, attack.t1136.001
// Description: Detects the creation of a new local user on a Fortinet FortiGate Firewall.
// The new local user could be used for VPN connections.
// Converted by: Sigma Universal SIEM/EDR CLI

(action: "Add" AND cfgpath: "user.local")
