# Vault server configuration for local demo
# Production would use HA config with Raft storage + TLS + auto-unseal

ui = true

# Storage backend — file-based for local demo
# Production: integrated Raft storage or Consul
storage "file" {
  path = "/vault/data"
}

# Listener — HTTP for local demo only
# Production: HTTPS with valid TLS certificates
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = "true"  # LOCAL DEMO ONLY — never disable TLS in production
}

# Disable mlock for Docker (containers don't support it by default)
# Production on bare metal: remove this line
disable_mlock = true

# API address for cluster communication
api_addr = "http://0.0.0.0:8200"

# Telemetry — optional, enables /v1/sys/metrics
telemetry {
  disable_hostname = true
}

# Log level
log_level = "info"
