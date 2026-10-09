// Title: Potential Data Stealing Via Chromium Headless Debugging
// ID: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-12-23
// Tags: attack.credential-access, attack.collection, attack.stealth, attack.t1185, attack.t1564.003
// Description: Detects chromium based browsers starting in headless and debugging mode and pointing to a user profile. This could be a sign of data stealing or remote control
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "*--remote-debugging-*" AND CommandLine: "*--user-data-dir*" AND CommandLine: "*--headless*"))
