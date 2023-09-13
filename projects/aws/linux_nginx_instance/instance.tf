
resource "aws_key_pair" "mykeyLinux" {
  key_name = "mykeyLinux"
  public_key = file(var.PUBLIC_KEY)
}

resource "aws_instance" "test" {
  ami           = "ami-0400d5cc4e83eab19"
  instance_type = "t2.micro"

  provisioner "file" {
      source      = "script.sh"
      destination = "/tmp/script.sh"
  }
  provisioner "remote-exec" {
      inline = [
        "chmod +x /tmp/script.sh",
        "sudo sed -i -e 's/\r$//' /tmp/script.sh",  # Remove the spurious CR characters.
        "sudo /tmp/script.sh",
      ]
  }
  connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = var.INSTANCE_USERNAME
      private_key = file(var.PATH_TO_PRIVATE_KEY)
    }
  }

