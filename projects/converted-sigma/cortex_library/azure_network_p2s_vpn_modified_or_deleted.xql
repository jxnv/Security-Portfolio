// Title: Azure Point-to-site VPN Modified or Deleted
// ID: d9557b75-267b-4b43-922f-a775e2d1f792
// Status: test
// Level: medium
// Author: Austin Songer @austinsonger
// Date: 2021-08-08
// Tags: attack.impact
// Description: Identifies when a Point-to-site VPN is Modified or Deleted.
// Converted by: Sigma Universal SIEM/EDR CLI

dataset = xdr_data | filter ((operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/WRITE" or operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/DELETE" or operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/RESET/ACTION" or operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/GENERATEVPNPROFILE/ACTION" or operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/DISCONNECTP2SVPNCONNECTIONS/ACTION" or operationName = "MICROSOFT.NETWORK/P2SVPNGATEWAYS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE"))
