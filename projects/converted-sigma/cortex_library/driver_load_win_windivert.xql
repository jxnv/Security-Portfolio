// Title: WinDivert Driver Load
// ID: 679085d5-f427-4484-9f58-1dc30a7c426d
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2021-07-30
// Tags: attack.credential-access, attack.collection, attack.defense-impairment, attack.t1599.001, attack.t1557.001
// Description: Detects the load of the Windiver driver, a powerful user-mode capture/sniffing/modification/blocking/re-injection package for Windows
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter (((ImageLoaded contains "\\WinDivert.sys" or ImageLoaded contains "\\WinDivert64.sys" or ImageLoaded contains "\\NordDivert.sys" or ImageLoaded contains "\\lingtiwfp.sys" or ImageLoaded contains "\\eswfp.sys")) or ((Hashes contains "IMPHASH=0604bb7cb4bb851e2168d5c7d9399087" or Hashes contains "IMPHASH=2e5f0e649d97f32b03c09e4686d0574f" or Hashes contains "IMPHASH=52f8aa269f69f0edad9e8fcdaedce276" or Hashes contains "IMPHASH=c0e5d314da39dbf65a2dbff409cc2c76" or Hashes contains "IMPHASH=58623490691babe8330adc81cd04a663" or Hashes contains "IMPHASH=8ee39b48656e4d6b8459d7ba7da7438b" or Hashes contains "IMPHASH=45ee545ae77e8d43fc70ede9efcd4c96" or Hashes contains "IMPHASH=a1b2e245acd47e4a348e1a552a02859a" or Hashes contains "IMPHASH=2a5f85fe4609461c6339637594fa9b0a" or Hashes contains "IMPHASH=6b2c6f95233c2914d1d488ee27531acc" or Hashes contains "IMPHASH=9f2fdd3f9ab922bbb0560a7df46f4342" or Hashes contains "IMPHASH=d8a719865c448b1bd2ec241e46ac1c88" or Hashes contains "IMPHASH=0ea54f8c9af4a2fe8367fa457f48ed38" or Hashes contains "IMPHASH=9d519ae0a0864d6d6ae3f8b6c9c70af6" or Hashes contains "IMPHASH=a74929edfc3289895e3f2885278947ae" or Hashes contains "IMPHASH=a66b476c2d06c370f0a53b5537f2f11e" or Hashes contains "IMPHASH=bdcd836a46bc2415773f6b5ea77a46e4" or Hashes contains "IMPHASH=c28cd6ccd83179e79dac132a553693d9")))
