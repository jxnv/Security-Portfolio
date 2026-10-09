// Title: New Kind of Network (NKN) Detection
// ID: fa7703d6-0ee8-4949-889c-48c84bc15b6f
// Status: test
// Level: low
// Author: Michael Portera (@mportatoes)
// Date: 2022-04-21
// Tags: attack.command-and-control
// Description: NKN is a networking service using blockchain technology to support a decentralized network of peers. While there are legitimate uses for it, it can also be used as a C2 channel. This rule looks for a DNS request to the ma>
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((query contains "seed" and query contains ".nkn.org"))
