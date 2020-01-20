resource "random_string" "this" {
  length  = 8
  special = false
  upper   = false
  number  = false
}

data "aws_vpc" "this" {
  id = "vpc-05411fb57f73c676d"
}

data "aws_subnet_ids" "this" {
  vpc_id = data.aws_vpc.this.id
}

locals {
  environment = random_string.this.result
}

module "elasticsearch" {
  source = "../../"

  vpc_id                               = data.aws_vpc.this.id
  environment                          = local.environment
  region                               = "ca-central-1"
  elasticsearch_domain_name            = format("es-%s", local.environment)
  elasticsearch_subnet_ids             = data.aws_subnet_ids.this.ids
  elasticsearch_data_instance_count    = "2"
  elasticsearch_dedicated_master_count = "0"
  elasticsearch_zone_awareness_enabled = true
  elasticsearch_az_count               = "2"
  elasticsearch_cognito_enabled        = true
  elasticsearch_snapshot_time          = "23"
  elasticsearch_data_instance_type     = "m5.large.elasticsearch"
  elasticsearch_ebs_volume_enabled     = true
  stack                                = "esb"
}
