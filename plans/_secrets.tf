variable "linode_token" {
  description = "The linode api token"
  type        = string
  sensitive   = true
}
variable "public_key" {
  description = "The linode authorized_key"
  type        = string
  default     = ""
}
variable "aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY"
  type        = string
  sensitive   = true
}
variable "aws_access_key_id" {
  description = "AWS_ACCESS_KEY_ID"
  type        = string
}
variable "allowed_linode_username" { # space delimited
  description = "ALLOWED_LINODE_USERNAME"
  type        = string
  default     = ""
}
variable "trivialsec_py_lib_ver" {
  description = "TRIVIALSEC_PY_LIB_VER"
  type        = string
}
variable "gitlab_user" {
  description = "GITLAB_USER"
  type        = string
}
variable "gitlab_password" {
  description = "GITLAB_PAT"
  type        = string
}
