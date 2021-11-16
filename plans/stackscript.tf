data "local_file" "public_api" {
    filename = "${path.root}/../bin/alpine-public-api"
}
resource "linode_stackscript" "public_api" {
  label = "public-api"
  description = "Installs public_api"
  script = data.local_file.public_api.content
  images = [local.linode_default_image]
  rev_note = "v1"
}
output "public_api_stackscript_id" {
  value = linode_stackscript.public_api.id
}
