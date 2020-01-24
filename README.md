# terraform-module-aws-elasticsearch

Terraform module to deploy AWS ElasticSearch Service

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| administrator\_access\_cidrs | List of CIDR's fron which users will have access to the application. | list | `[ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]` | no |
| cognito\_idp\_client\_id | Id of the client app in cognito | string | n/a | yes |
| cognito\_idp\_sso\_redirect | URL of the identity provider | string | n/a | yes |
| cognito\_provider\_name | Name of the identity provider | string | n/a | yes |
| cognito\_server\_side\_token\_check | Whether or not token should be check on server side | string | `"true"` | no |
| elasticsearch\_az\_count | Number of Availability Zones for the domain. | string | n/a | yes |
| elasticsearch\_cognito\_enabled | Wether to activate cognito configuration. | string | `"false"` | no |
| elasticsearch\_data\_instance\_count | Number of data instances to create in elasticsearch cluster. | string | n/a | yes |
| elasticsearch\_data\_instance\_type | Type of instance for elasticsearch data nodes. | string | `"t2.small.elasticsearch"` | no |
| elasticsearch\_dedicated\_master | whether or not dedicated master nodes are enabled for the cluster. | string | `"false"` | no |
| elasticsearch\_dedicated\_master\_count | Number of master instances to create in elasticsearch cluster. | string | n/a | yes |
| elasticsearch\_dedicated\_master\_type | Type of instance for elasticsearch master nodes. | string | `"t2.small.elasticsearch"` | no |
| elasticsearch\_domain\_name | Name of the elasticsearch domain. | string | n/a | yes |
| elasticsearch\_ebs\_iops | baseline input/output performance of EBS volumes attached to data nodes. | string | `"150"` | no |
| elasticsearch\_ebs\_volume\_enabled | Whether EBS volumes are attached to data nodes. | string | `"false"` | no |
| elasticsearch\_ebs\_volume\_size | Size of EBS volumes attached to data nodes. | string | `"50"` | no |
| elasticsearch\_ebs\_volume\_type | Type of EBS volumes attached to data nodes. | string | `"gp2"` | no |
| elasticsearch\_encrypt\_at\_rest\_enabled | Wether to enable encryption at rest. | string | `"true"` | no |
| elasticsearch\_node2node\_encryption | Whether to enable node-to-node encryption. | string | `"true"` | no |
| elasticsearch\_snapshot\_time | Hour during which the service takes an automated daily snapshot of the indices in the domain. | string | n/a | yes |
| elasticsearch\_subnet\_ids | List of subnets where elasticsearch will be deployed. | list(string) | n/a | yes |
| elasticsearch\_version | Version of elasticsearch to use. | string | `"7.1"` | no |
| elasticsearch\_zone\_awareness\_enabled | Whether or not zone awareness is enabled. | string | `"false"` | no |
| environment | Name of the environment the module belongs to. | string | n/a | yes |
| region | Region where elasticsearch cluster will be deployed. | string | n/a | yes |
| sg\_tags | Tags to applt on the security groups of the module. | map | `{}` | no |
| stack | Name of the stack for which cognito is deployed | string | n/a | yes |
| tags | Map of tags to apply to all resources of the module \(where applicable\). | map | `{}` | no |
| vpc\_id | Id of the vpc where elasticsearch cluster will be deployed. | string | n/a | yes |

<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
