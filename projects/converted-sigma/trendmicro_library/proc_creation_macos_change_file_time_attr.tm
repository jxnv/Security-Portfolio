// Title: File Time Attribute Change
// ID: 88c0f9d8-30a8-4120-bb6b-ebb54abcf2a0
// Status: test
// Level: medium
// Author: Igor Fits, Mikhail Larin, oscd.community
// Date: 2020-10-19
// Tags: attack.stealth, attack.t1070.006
// Description: Detect file time attribute change to hide new or changes to existing files
// Converted by: Sigma Universal SIEM/EDR CLI

(Image="*/touch" AND (CommandLine: "*-t*" OR CommandLine: "*-acmr*" OR CommandLine: "*-d*" OR CommandLine: "*-r*"))
