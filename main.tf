#####
# AWS ElasticSearch 
#####

resource "aws_kms_key" "this" {
  description = "KMS key for the ESB module."

  tags = merge(
    {
      "Terraform" = "true"
      "Name"      = format("esb-%s-application-kms_key", var.environment)
    },
    var.tags,
  )
}

resource "aws_elasticsearch_domain" "this" {
  domain_name           = var.elasticsearch_domain_name
  elasticsearch_version = var.elasticsearch_version

  cluster_config {
    instance_type  = var.elasticsearch_data_instance_type
    instance_count = var.elasticsearch_data_instance_count 

    dedicated_master_enabled = var.elasticsearch_dedicated_master
    dedicated_master_type    = var.elasticsearch_dedicated_master_type
    dedicated_master_count   = var.elasticsearch_dedicated_master_count

    zone_awareness_enabled = var.elasticsearch_zone_awareness_enabled

    zone_awareness_config {
      availability_zone_count = var.elasticsearch_az_count
    }
  }

  node_to_node_encryption {
    enabled = var.elasticsearch_node2node_encryption
  }

  encrypt_at_rest {
    enabled    = var.elasticsearch_encrypt_at_rest_enabled

    kms_key_id = aws_kms_key.this.arn
  }

  ebs_options {
    ebs_enabled = var.elasticsearch_ebs_volume_enabled

    volume_size = var.elasticsearch_ebs_volume_size
    volume_type = var.elasticsearch_ebs_volume_type
    iops        = var.elasticsearch_ebs_iops
  }


/*
  cognito_options {
    enabled = var.elasticsearch_cognito_enabled

    user_pool_id     = var.elasticsearch_cognito_user_pool_id
    identity_pool_id = var.elasticsearch_cognito_identity_pool_id
    role_arn         = var.elasticsearch_cognito_role_arn
  }
*/

  snapshot_options {
    automated_snapshot_start_hour = var.elasticsearch_snapshot_time
  }


  tags = {
    Domain = var.elasticsearch_domain_name
  }

  vpc_options {
    subnet_ids = var.elasticsearch_subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }
}

resource "aws_security_group" "this" { }
