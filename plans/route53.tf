resource "aws_route53_record" "public_api_a" {
    zone_id = local.route53_hosted_zone
    name    = local.instance_hostname
    type    = "A"
    ttl     = 300
    records = linode_instance.public_api.ipv4
}
resource "aws_route53_record" "public_api_aaaa" {
    zone_id = local.route53_hosted_zone
    name    = local.instance_hostname
    type    = "AAAA"
    ttl     = 300
    records = [
        element(split("/", linode_instance.public_api.ipv6), 0)
    ]
}
