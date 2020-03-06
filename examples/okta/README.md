This provides an example on how to configure the plugin to work with Okta service.

- Create a developer account in Okta
- Create 3 applications of type `service-to-service`, named them: `client1`, `client2` and `introspectClient`
- Create 2 custom authorization servers with `aud` corresponding to `geth` node name (which is configured via `--identity`), (e.g.: `node1` and `node2`)
- Add scopes to the above authorization servers. Scopes describe RPC APIs. E.g.: `rpc://admin_*`, `rpc://rpc_modules` ...