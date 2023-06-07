#kubectl create secret generic gateway-ca-bundle --from-file=./ca.crt
resource "kubernetes_secret" "gateway_ca_bundle" {
  metadata {
    name      = "gateway-ca-bundle-new"
    namespace = "default"
  }
  data = {
    "ca.crt" = base64decode(var.ca_bundle_b64)
  }
}
