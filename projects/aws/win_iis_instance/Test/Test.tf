terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
    access_key = "AKIAZ5BNUHGQOGX5IHHD"
    secret_key = "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"
    region     = "ap-south-1"
}



# Get latest Windows Server 2019 AMI
data "aws_ami" "windows-2022" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Core-Base*"]
  }
}
