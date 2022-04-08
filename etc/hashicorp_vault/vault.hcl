path "secret/" {
  capabilities = ["list"]
}

path "secret/metadata" {
  capabilities = ["list"]
}

path "secret/metadata/dienes/*" {
  capabilities = ["list"]
}

path "secret/data/dienes/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/dienes/*" {
	capabilities = ["read", "list"]
}
