// Title: Potential File Extension Spoofing Using Right-to-Left Override
// ID: 979baf41-ca44-4540-9d0c-4fcef3b5a3a4
// Status: test
// Level: high
// Author: Jonathan Peters (Nextron Systems), Florian Roth (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
// Date: 2024-11-17
// Tags: attack.execution, attack.stealth, attack.t1036.002
// Description: Detects suspicious filenames that contain a right-to-left override character and a potentially spoofed file extensions.
// Converted by: Sigma Universal SIEM/EDR CLI

(((TargetFilename: "*3pm.*" OR TargetFilename: "*4pm.*" OR TargetFilename: "*cod.*" OR TargetFilename: "*fdp.*" OR TargetFilename: "*ftr.*" OR TargetFilename: "*gepj.*" OR TargetFilename: "*gnp.*" OR TargetFilename: "*gpj.*" OR TargetFilename: "*ism.*" OR TargetFilename: "*lmth.*" OR TargetFilename: "*nls.*" OR TargetFilename: "*piz.*" OR TargetFilename: "*slx.*" OR TargetFilename: "*tdo.*" OR TargetFilename: "*vsc.*" OR TargetFilename: "*vwm.*" OR TargetFilename: "*xcod.*" OR TargetFilename: "*xslx.*" OR TargetFilename: "*xtpp.*")) AND ((TargetFilename: "*\\u202e*" OR TargetFilename: "*[U+202E]*" OR TargetFilename: "*‮*")))
