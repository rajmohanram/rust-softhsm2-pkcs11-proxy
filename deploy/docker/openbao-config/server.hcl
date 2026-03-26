ui = true
disable_mlock = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/openbao/data"
}

seal "pkcs11" {
  lib         = "/usr/local/lib/libpkcs11-proxy.so"
  token_label = "openbao"
  pin         = "5678"
  key_label   = "openbao-unseal"
  mechanism   = "CKM_AES_GCM"
}
