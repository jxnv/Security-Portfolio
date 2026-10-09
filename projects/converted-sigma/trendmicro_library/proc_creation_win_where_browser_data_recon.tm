// Title: Suspicious Where Execution
// ID: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
// Status: test
// Level: low
// Author: frack113, Nasreddine Bencherchali (Nextron Systems)
// Date: 2021-12-13
// Tags: attack.discovery, attack.t1217
// Description: Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
// Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
// internal network resources such as servers, tools/dashboards, or other related infrastructure.
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\where.exe") OR (OriginalFileName: "where.exe")) AND ((CommandLine: "*places.sqlite*" OR CommandLine: "*cookies.sqlite*" OR CommandLine: "*formhistory.sqlite*" OR CommandLine: "*logins.json*" OR CommandLine: "*key4.db*" OR CommandLine: "*key3.db*" OR CommandLine: "*sessionstore.jsonlz4*" OR CommandLine: "*History*" OR CommandLine: "*Bookmarks*" OR CommandLine: "*Cookies*" OR CommandLine: "*Login Data*")))
