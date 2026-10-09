// Title: Telegram Bot API Request
// ID: c64c5175-5189-431b-a55e-6d9882158251
// Status: test
// Level: medium
// Author: Florian Roth (Nextron Systems)
// Date: 2018-06-05
// Tags: attack.command-and-control, attack.t1102.002
// Description: Detects suspicious DNS queries to api.telegram.org used by Telegram Bots of any kind
// Converted by: Sigma Universal SIEM/EDR CLI

(query: "api.telegram.org")
