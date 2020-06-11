#!/bin/bash

echo -n "<app-plugin Client ID> "
read client_id
echo -n "<app-plugin Client Secret> "
read client_secret

folders=(node-0 node-1 node-2)
for i in "${!folders[@]}"; do
  f="${folders[$i]}"
  id=$(expr $i + 1)
  echo "Populate okta-config.json for node $id"
  echo -n "<issuer $id> "
  read issuer
  echo -n "<introspection_endpoint $id> "
  read introspection_endpoint
  jq ".tokenValidation.introspect.endpoint = \"$introspection_endpoint\"
    | .tokenValidation.issuers = [\"$issuer\"]
    | .tokenValidation.introspect.authentication.credentials.clientId = \"$client_id\"
    | .tokenValidation.introspect.authentication.credentials.clientSecret = \"$client_secret\"" \
    $f/okta-config-template.json > $f/okta-config.json
done