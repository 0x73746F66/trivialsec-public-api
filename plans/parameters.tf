resource "aws_ssm_parameter" "ssm_linode_public_api_password" {
  name        = "/linode/${linode_instance.public_api.id}/linode_public_api_password"
  description = join(", ", linode_instance.public_api.ipv4)
  type        = "SecureString"
  value       = random_string.linode_password.result
  tags = {
    cost-center = "saas"
  }
}
