// Title: Potential Homoglyph Attack Using Lookalike Characters in Filename
// ID: 4f1707b1-b50b-45b4-b5a2-3978b5a5d0d6
// Status: test
// Level: medium
// Author: Micah Babinski, @micahbabinski
// Date: 2023-05-08
// Tags: attack.stealth, attack.t1036, attack.t1036.003
// Description: Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
// This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
// are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((action_file_path contains "а" or action_file_path contains "е" or action_file_path contains "о" or action_file_path contains "р" or action_file_path contains "с" or action_file_path contains "х" or action_file_path contains "ѕ" or action_file_path contains "і" or action_file_path contains "ӏ" or action_file_path contains "ј" or action_file_path contains "һ" or action_file_path contains "ԁ" or action_file_path contains "ԛ" or action_file_path contains "ԝ" or action_file_path contains "ο")) or ((action_file_path contains "А" or action_file_path contains "В" or action_file_path contains "Е" or action_file_path contains "К" or action_file_path contains "М" or action_file_path contains "Н" or action_file_path contains "О" or action_file_path contains "Р" or action_file_path contains "С" or action_file_path contains "Т" or action_file_path contains "Х" or action_file_path contains "Ѕ" or action_file_path contains "І" or action_file_path contains "Ј" or action_file_path contains "Ү" or action_file_path contains "Ӏ" or action_file_path contains "Ԍ" or action_file_path contains "Ԛ" or action_file_path contains "Ԝ" or action_file_path contains "Α" or action_file_path contains "Β" or action_file_path contains "Ε" or action_file_path contains "Ζ" or action_file_path contains "Η" or action_file_path contains "Ι" or action_file_path contains "Κ" or action_file_path contains "Μ" or action_file_path contains "Ν" or action_file_path contains "Ο" or action_file_path contains "Ρ" or action_file_path contains "Τ" or action_file_path contains "Υ" or action_file_path contains "Χ")))
