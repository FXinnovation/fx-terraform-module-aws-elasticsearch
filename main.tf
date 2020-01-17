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

resource "aws_iam_service_linked_role" "this" {
  aws_service_name = "es.amazonaws.com"
}

resource "aws_iam_role" "this" {
  name = format("%s-%s-es-iam-role", var.stack, var.environment)

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "this" {
  name       = format("%s-%s-es-iam-role-attachment", var.stack, var.environment)
  roles      = [aws_iam_role.this.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonESCognitoAccess"
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
    enabled = var.elasticsearch_encrypt_at_rest_enabled

    kms_key_id = aws_kms_key.this.arn
  }

  ebs_options {
    ebs_enabled = var.elasticsearch_ebs_volume_enabled

    volume_size = var.elasticsearch_ebs_volume_size
    volume_type = var.elasticsearch_ebs_volume_type
  }


  cognito_options {
    enabled = var.elasticsearch_cognito_enabled

    user_pool_id     = aws_cognito_user_pool.this.id
    identity_pool_id = aws_cognito_identity_pool.this.id
    role_arn         = aws_iam_role.this.arn
  }

  snapshot_options {
    automated_snapshot_start_hour = var.elasticsearch_snapshot_time
  }


  tags = {
    Domain = var.elasticsearch_domain_name
  }

  vpc_options {
    subnet_ids         = var.elasticsearch_subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  depends_on = [
    "aws_iam_service_linked_role.this",
  ]
}

#####
# AWS Cognito
#####

resource "aws_iam_role" "authenticated" {
  name = format("%s-%s-authenticated-role", var.stack, var.environment)

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.this.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "authenticated" {
  name = format("%s-%s-authenticated-policy", var.stack, var.environment)
  role = aws_iam_role.authenticated.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role" "unauthenticated" {
  name = format("%s-%s-unauthenticated-role", var.stack, var.environment)

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.this.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "unauthenticated" {
  name = format("%s-%s-unauthenticated-policy", var.stack, var.environment)
  role = aws_iam_role.unauthenticated.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "mobileanalytics:PutEvents",
        "cognito-sync:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.this.id

  roles = {
    "authenticated"   = aws_iam_role.authenticated.arn,
    "unauthenticated" = aws_iam_role.unauthenticated.arn
  }
}

resource "aws_iam_saml_provider" "default" {
  name                   = format("%s-%s-saml-provider", var.stack, var.environment)
  saml_metadata_document = file("${path.module}/../../../saml-metadata.xml")
}

resource "aws_cognito_identity_pool" "this" {
  identity_pool_name               = format("%s %s identity pool", var.stack, var.environment)
  allow_unauthenticated_identities = false

  saml_provider_arns = [aws_iam_saml_provider.default.arn]
}

resource "aws_cognito_user_pool" "this" {
  name = format("%s-%s-user-pool", var.stack, var.environment)
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = format("%s-%s-es", var.stack, var.environment)
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_identity_provider" "this" {
  user_pool_id  = aws_cognito_user_pool.this.id
  provider_name = format("%s-%s-provider", var.stack, var.environment)
  provider_type = "SAML"
  attribute_mapping = {
    email = "email"
  }
  provider_details = {
    MetadataFile = file("${path.module}/../../../saml-metadata.xml")
  }
}

resource "aws_security_group" "this" {
  vpc_id      = var.vpc_id
}
