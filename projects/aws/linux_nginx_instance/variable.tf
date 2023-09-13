variable "AWS_ACCESS_KEY" {}
variable "AWS_SECRET_KEY" {}
variable "AWS_REGION" {
    default = "ap-southeast-1"
}


variable "PATH_TO_PRIVATE_KEY" {
  default = ("./mykeyLinux")
}

variable "PUBLIC_KEY" {
    default = ("./mykeyLinux.pub")
}

variable "INSTANCE_USERNAME" {
  default = "ubuntu"
}
