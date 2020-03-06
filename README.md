This is to provide a backend support for `geth` JSON RPC servers by implementing services from [security plugin interface](https://github.com/jpmorganchase/quorum-plugin-definitions/blob/master/security.proto):

- `TLSConfigurationSource` to provide TLS configuration for HTTP and WS RPC servers
- `AuthenticationManager` to enable RPC servers being OAuth2-compliant resource servers 
that support both JSON Web Token ([JWT](https://tools.ietf.org/html/rfc7519)) and opaque access token format

## Prerequisites

* Go 1.13.x

## Quick Start

```bash
$ go mod vendor
$ make
$ PLUGIN_DIST_PATH=<path to store plugin distribution zip file> make dist
```

## Configuration

Refer to the official documentation [here](http://docs.goquorum.com/en/latest/PluggableArchitecture/Plugins/security/implementation/) for more details

## Token Validation

Access token is validated by one of the following methods when configured:

- [JSON Web Signature](https://tools.ietf.org/html/rfc7515): The JSON Web Key Set ([JWKS](https://tools.ietf.org/html/rfc7517)) is a set of keys which contains the public keys used to verify 
the JSON Web Token (JWT) issued by the authorization server. JWKS is retrieved via a preconfigured endpoint.
- [OAuth2 Token Introspection](https://tools.ietf.org/html/rfc7662): support HTTP Basic Authentication and Form Authentication 
to access the protected introspection endpoint. Other authentication methods may be supported in the future.