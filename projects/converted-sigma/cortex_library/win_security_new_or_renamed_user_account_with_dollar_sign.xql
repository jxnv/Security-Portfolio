// Title: New or Renamed User Account with '$' Character
// ID: cfeed607-6aa4-4bbd-9627-b637deb723c8
// Status: test
// Level: medium
// Author: Ilyas Ochkov, oscd.community
// Date: 2019-10-25
// Tags: attack.stealth, attack.t1036
// Description: Detects the creation of a user with the "$" character. This can be used by attackers to hide a user or trick detection systems that lack the parsing mechanisms.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((EventID = 4720 and SamAccountName contains "$") or (EventID = 4781 and NewTargetUserName contains "$")) and not ((EventID = 4720 and TargetUserName = "HomeGroupUser$")))
