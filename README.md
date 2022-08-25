# Palo Alto Framework

This is a framework that connects to the API of Palo Alto firewalls.

## Authentication

Credentials are stored in JSON format, in the same directory as the `palo.py` file. The name of the file should be `credentials.json`.

Other authentication methods, such as KDBX, have been tested, but this way it keeps the hard-coded passwords out of the source code.

```
{
	"credentials": {
		"device01": {
			"username": "",
			"password": "",
			"token": ""
		},
		"device02": {
			"username": "",
			"password": "",
			"token": ""
		}
	}
}
```

The FQDN/IP/Hostname of the device will be referenced in the credential file, so the values must match to authenticate.

A separate function `login()` will need to be invoked to authenticate to the appliance, afterward a token will be automatically generated to remain authenticated.

## Getting Started

To instantiate a `PaloAlto` object, pass a string of the server name that also matches the JSON credential mentioned in the "Authentication" section :

```
>>> hostname = 'palo01.domain.com'
>>> p = PaloAlto(hostname)
```

Then, to log into the appliance, invoke the `login()` function :

```
>>> p.login()
```

## Palo Alto API Features

There are a tremendous amount of features available via API.

The VPN creation mechanism has saved thousands of hours of clicking when creating IPSec proxy traffic.

Also, another time-saving mechanism is adding large Object and Object-group definitions via API.

Some functions are written via the REST API, but most are done through XML interactions for reasons of speed.

REST Functions :
- Get list of objects
- Get list of policies
- Get list of VSYS
- Add a rule
- Edit a rule
- Delete a rule
- Get a rule
- Add a member to a rule

Most features of the XML API to retrieve, set, update, and delete data are written :
- Create Zone
- Create Policy
- Create IPSec
- Create IKE Crypto
- Create IKE Gateway
- Create IPSec Crypto
- Create Tunnel Interface
- Create NAT
- Create Object
- Create Object-group
- Set IKE Gateway Peer
- Set IKE Gateway Interface
- Set IKE Gateway IP
- Set IKE Gateway NAT
- Set IKE Gateway Crypto Profile
- Set IKE Gateway PSK
- Set IKE Crypto DH Group
- Set IKE Crypto Encryption
- Set IKE Crypto Hash
- Set IKE Crypto Lifetime
- Set IPSec Crypto Gateway
- Set IPSec Crypto Profile
- Set IPSec Crypto Protocol
- Set IPSec Crypto DH Group
- Set IPSec Crypto Encryption
- Set IPSec Crypto Hash
- Set IPSec Crypto Lifetime
- Set IPSec Crypto Tunnel Interface
- Set Policy Source Zone
- Set Policy Destination Zone
- Set Policy Service
- Set Policy Application
- Set Policy User
- Set Policy Source
- Set Policy Destination
- Set Policy Category
- Set Policy Action
- Set Policy Enable/Disable
- Set Zone Interface
- Set Router Interface
- Set Router Interface for Redistribution
- Set NAT Source Zone
- Set NAT Destination Zone
- Set NAT Source IP
- Set NAT Destination IP
- Set NAT Service
- Set NAT Description
- Set NAT Destination Translation Address
- Set IPSec Proxy
- Set IPSec Proxy (from CSV file)
- Set Object IP
- Set Object-group Object
- Get list of zones
- Get list of policies
- Get list of tunnel interfaces

A few custom functions were created to create VPNs and NAT translations :
- Create VPN `create_vpn()`
- Create NAT Translation `create_nat_translation()`

The custom scripts would need to be modified according to personal preference or standardization.