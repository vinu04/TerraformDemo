variable "AWS_ACCESS_KEY" {}
variable "AWS_SECRET_KEY" {}
variable "AWS_REGION" {
    default = "ap-southeast-1"
}

variable "PATH_TO_PRIVATE_KEY" {
  default = ("./mykey")
}
variable "KEY_NAME" { 
  default = "mykey" 
}

variable "PUBLIC_KEY" {
    default = ("./mykey.pub")
}


variable "INSTANCE_USERNAME" { 
  default = "admin" 
  } 
variable "INSTANCE_PASSWORD" {
  }