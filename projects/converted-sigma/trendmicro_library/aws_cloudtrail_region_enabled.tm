// Title: AWS EnableRegion Command Monitoring
// ID: a5ffb6ea-c784-4e01-b30a-deb6e58ca2ab
// Status: experimental
// Level: medium
// Author: Ivan Saakov, Sergey Zelenskiy
// Date: 2025-10-19
// Tags: attack.persistence
// Description: Detects the use of the EnableRegion command in AWS CloudTrail logs.
// While AWS has 30+ regions, some of them are enabled by default, others must be explicitly enabled in each account separately.
// There may be situations where security monitoring does not cover some new AWS regions.
// Monitoring the EnableRegion command is important for identifying potential persistence mechanisms employed by adversaries, as enabling additional regions can facilitate continued access and operations within an AWS environment.
// Converted by: Sigma Universal SIEM/EDR CLI

(eventName: "EnableRegion" AND eventSource: "account.amazonaws.com")
