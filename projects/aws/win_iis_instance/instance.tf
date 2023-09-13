resource "aws_key_pair" "mykey" {
  key_name = "mykey"
  public_key = file(var.PUBLIC_KEY)
}

# Default security group to access the instances via WinRM over HTTP and HTTPS
resource "aws_security_group" "default" {
  name        = "terraform_example"
  description = "Windows Test using terraform"

  # WinRM access from anywhere
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 8088
    to_port     = 8088
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
# Lookup the correct AMI based on the region specified
data "aws_ami" "windows-2022" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Core-Base*"]
  }
}


resource "aws_instance" "winrm" {
  # The connection block tells our provisioner how to
  # communicate with the resource (instance)
  connection {
    type     = "winrm"
    user     = "Administrator"
    password = var.INSTANCE_PASSWORD

    # set from default of 5m to 10m to avoid winrm timeout
    timeout = "10m"
  }

  instance_type = "t2.micro"
  ami           = data.aws_ami.windows-2022.image_id
 
  associate_public_ip_address = "true"
  vpc_security_group_ids = [aws_security_group.default.id]
  #subnet_id              = "subnet-eddcdzz4"

  # The name of our SSH keypair you've created and downloaded
  # from the AWS console.
  #
  # https://console.aws.amazon.com/ec2/v2/home?region=us-west-2#KeyPairs
  #
  key_name = var.KEY_NAME

  # Our Security group to allow WinRM access
  security_groups = [aws_security_group.default.name]

  # Note that terraform uses Go WinRM which doesn't support https at this time. If server is not on a private network,
  # recommend bootstraping Chef via user_data.  See asg_user_data.tpl for an example on how to do that.
  user_data = <<EOF
<script>
  winrm quickconfig -q & winrm set winrm/config @{MaxTimeoutms="1800000"} & winrm set winrm/config/service @{AllowUnencrypted="true"} & winrm set winrm/config/service/auth @{Basic="true"}
</script>
<powershell>
  netsh advfirewall firewall add rule name="WinRM in" protocol=TCP dir=in profile=any localport=5985 remoteip=any localip=any action=allow
  netsh advfirewall firewall add rule name="Web in" protocol=TCP dir=in profile=any localport=8088 remoteip=any localip=any action=allow
  # Set Administrator password
  $admin = [adsi]("WinNT://./administrator, user")
  $admin.psbase.invoke("SetPassword", "${var.INSTANCE_PASSWORD}")
  
  # Install IIS Features and Roles
  Install-WindowsFeature -name Web-Server -IncludeManagementTools

  # Disable IE Security Function
  function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
  }

  #HTMLFile
  function Setup-MyWebSite {
     New-Item c:\INETPUB\MYWEBSITE -ItemType Directory
    New-Item c:\INETPUB\Mywebsite\index.html -ItemType File
    Set-Content c:\INETPUB\Mywebsite\index.html '<!DOCTYPE html><html><head><title>IIS Deployment Automation Demo for HSBC banking Group</title></head><body><h1>IIS Administration Automation Demo for HSBC Banking Group</h1><p>Thank you for reading this post on how to administer IIS with Terraform!</p><p>This page was created using the newer IISAdministration PowerShell module + Terraform Deployment.</p><h2>First Steps</h2><p>Keep calm and learn PowerShell.</p></body></html>'
    New-IISSite -Name 'MyWebsite' -PhysicalPath 'c:\INETPUB\Mywebsite\' -BindingInformation "*:8088:"
  }

  # Disable UAC Function
  function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green    
  }
  # Disable IE Sec and UAC
  Disable-InternetExplorerESC
  Disable-UserAccessControl
  Setup-MyWebSite
  #Set Time Zone
  Set-TimeZone -id "India Standard Time"

  Restart-Computer

</powershell>
EOF
}
