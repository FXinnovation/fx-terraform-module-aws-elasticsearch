variable "vpc_id" {
  description = "Id of the vpc where elasticsearch cluster will be deployed."
  type        = string
}

variable "environment" {
  description = "Name of the environment the module belongs to."
  type        = string
}

variable "region" {
  description = "Region where elasticsearch cluster will be deployed."
  type        = string
}

variable "tags" {
  description = "Map of tags to apply to all resources of the module (where applicable)."
  default     = {}
}

variable "elasticsearch_domain_name" {
  description = "Name of the elasticsearch domain."
  type        = string
}

variable "elasticsearch_version" {
  description = "Version of elasticsearch to use."
  default     = "7.1"
}

variable "elasticsearch_subnet_ids" {
  description = "List of subnets where elasticsearch will be deployed."
  type        = list(string)
}

variable "elasticsearch_data_instance_type" {
  description = "Type of instance for elasticsearch data nodes."
  default     = "t2.small.elasticsearch"
}

variable "elasticsearch_data_instance_count" {
  description = "Number of data instances to create in elasticsearch cluster."
  type        = string
}

variable "elasticsearch_dedicated_master" {
  description = "whether or not dedicated master nodes are enabled for the cluster."
  default     = false
}

variable "elasticsearch_dedicated_master_type" {
  description = "Type of instance for elasticsearch master nodes."
  default     = "t2.small.elasticsearch"
}

variable "elasticsearch_dedicated_master_count" {
  description = "Number of master instances to create in elasticsearch cluster."
  type        = string
}

variable "elasticsearch_zone_awareness_enabled" {
  description = "Whether or not zone awareness is enabled."
  default     = false
}

variable "elasticsearch_az_count" {
  description = "Number of Availability Zones for the domain."
  type        = string
}

variable "elasticsearch_node2node_encryption" {
  description = "Whether to enable node-to-node encryption."
  default     = true
}

variable "elasticsearch_encrypt_at_rest_enabled" {
  description = "Wether to enable encryption at rest."
  default     = true
}

variable "elasticsearch_ebs_volume_enabled" {
  description = "Whether EBS volumes are attached to data nodes."
  default     = false
}

variable "elasticsearch_ebs_volume_size" {
  description = "Size of EBS volumes attached to data nodes."
  default     = "50"
}

variable "elasticsearch_ebs_volume_type" {
  description = "Type of EBS volumes attached to data nodes."
  default     = "gp2"
}

variable "elasticsearch_ebs_iops" {
  description = "baseline input/output performance of EBS volumes attached to data nodes."
  default     = "150"
}

variable "elasticsearch_cognito_enabled" {
  description = "Wether to activate cognito configuration."
  default     = false
}

variable "elasticsearch_snapshot_time" {
  description = "Hour during which the service takes an automated daily snapshot of the indices in the domain."
  type        = string
}

variable "administrator_access_cidrs" {
  description = "List of CIDR's fron which users will have access to the application."
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "sg_tags" {
  description = "Tags to applt on the security groups of the module."
  default     = {}
}

#####
# AWS Cognito
#####

variable "stack" {
  description = "Name of the stack for which cognito is deployed"
  type        = string
}

variable "cognito_idp_client_id" {
  description = "Id of the client app in cognito"
  type        = string
}

variable "cognito_provider_name" {
  description = "Name of the identity provider"
  type        = string
}

variable "cognito_server_side_token_check" {
  description = "Whether or not token should be check on server side"
  default     = true
}

variable "cognito_idp_sso_redirect" {
  description = "URL of the identity provider"
  type        = string
}
