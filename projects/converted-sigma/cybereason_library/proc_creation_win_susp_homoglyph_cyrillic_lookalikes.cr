// Title: Potential Homoglyph Attack Using Lookalike Characters
// ID: 32e280f1-8ad4-46ef-9e80-910657611fbc
// Status: test
// Level: medium
// Author: Micah Babinski, @micahbabinski
// Date: 2023-05-07
// Tags: attack.stealth, attack.t1036, attack.t1036.003
// Description: Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
// This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
// are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "а" OR CommandLine contains "е" OR CommandLine contains "о" OR CommandLine contains "р" OR CommandLine contains "с" OR CommandLine contains "х" OR CommandLine contains "ѕ" OR CommandLine contains "і" OR CommandLine contains "ӏ" OR CommandLine contains "ј" OR CommandLine contains "һ" OR CommandLine contains "ԁ" OR CommandLine contains "ԛ" OR CommandLine contains "ԝ" OR CommandLine contains "ο")) OR ((CommandLine contains "А" OR CommandLine contains "В" OR CommandLine contains "Е" OR CommandLine contains "К" OR CommandLine contains "М" OR CommandLine contains "Н" OR CommandLine contains "О" OR CommandLine contains "Р" OR CommandLine contains "С" OR CommandLine contains "Т" OR CommandLine contains "Х" OR CommandLine contains "Ѕ" OR CommandLine contains "І" OR CommandLine contains "Ј" OR CommandLine contains "Ү" OR CommandLine contains "Ӏ" OR CommandLine contains "Ԍ" OR CommandLine contains "Ԛ" OR CommandLine contains "Ԝ" OR CommandLine contains "Α" OR CommandLine contains "Β" OR CommandLine contains "Ε" OR CommandLine contains "Ζ" OR CommandLine contains "Η" OR CommandLine contains "Ι" OR CommandLine contains "Κ" OR CommandLine contains "Μ" OR CommandLine contains "Ν" OR CommandLine contains "Ο" OR CommandLine contains "Ρ" OR CommandLine contains "Τ" OR CommandLine contains "Υ" OR CommandLine contains "Χ")))
