variable "AWS_ACCESS_KEY" {}
variable "AWS_SECRET_KEY" {}
variable "AWS_REGION" {
    default = "ap-southeast-1"
}

variable "PATH_TO_PRIVATE_KEY" {
  default = ("./mykeySQL")
}
variable "KEY_NAME" { 
  default = "mykeySQL" 
}

variable "PUBLIC_KEY" {
    default = ("./mykeySQL.pub")
}


variable "INSTANCE_USERNAME" { 
  default = "admin" 
  } 
variable "INSTANCE_PASSWORD" {
  }