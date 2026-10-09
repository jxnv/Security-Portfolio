// Title: Suspicious CodePage Switch Via CHCP
// ID: c7942406-33dd-4377-a564-0f62db0593a3
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community
// Date: 2019-10-14
// Tags: attack.stealth, attack.t1036
// Description: Detects a code page switch in command line or batch scripts to a rare language
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*\\chcp.com" AND (CommandLine="* 936" OR CommandLine="* 1258"))
