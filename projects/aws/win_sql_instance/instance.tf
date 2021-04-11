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
  

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
# Lookup the correct AMI based on the region specified
data "aws_ami" "amazon_windows_2019_sql_2017_std" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-SQL_2017_Standard-*"]
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

 instance_type = "m4.large"
 ami           = data.aws_ami.amazon_windows_2019_sql_2017_std.image_id

  root_block_device {
      volume_type = "gp2"
      volume_size = 80
      delete_on_termination = true
    }

    # Slave Storage
    ebs_block_device {
      device_name = "/dev/xvdb"
      volume_type = "sc1"
      volume_size = 500
      encrypted = "true"
      delete_on_termination = true
    }

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
    
  Initialize-Disk 1 -PartitionStyle GPT
    New-Partition –DiskNumber 1 -UseMaximumSize -AssignDriveLetter
    Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel SQL-Stuff
    New-Item -ItemType directory -Path D:\Data
    New-Item -ItemType directory -Path D:\Backup
    New-Item -ItemType directory -Path D:\Log
    # Set Default Paths for MSSQL Dirs
    $DataRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
    $DataRegKeyName = "DefaultData"
    $DataDirectory = "D:\Data"
      If ((Get-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
      New-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -PropertyType String -Value $DataDirectory
        } Else {
        Set-ItemProperty -Path $DataRegKeyPath -Name $DataRegKeyName -Value $DataDirectory
    }
    $LogRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
    $LogRegKeyName = "DefaultLog"
    $LogDirectory = "D:\Log"
      If ((Get-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
      New-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -PropertyType String -Value $LogDirectory
        } Else {
        Set-ItemProperty -Path $LogRegKeyPath -Name $LogRegKeyName -Value $LogDirectory
    }
    $BackupRegKeyPath = "HKLM:\Software\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer"
    $BackupRegKeyName = "BackupDirectory"
    $BackupDirectory = "D:\Backup"
      If ((Get-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -ErrorAction SilentlyContinue) -eq $null) {
      New-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -PropertyType String -Value $BackupDirectory
        } Else {
        Set-ItemProperty -Path $BackupRegKeyPath -Name $BackupRegKeyName -Value $BackupDirectory
    }

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
    Set-Content c:\INETPUB\Mywebsite\index.html '<!DOCTYPE html><html><head><title>IIS Administration With PowerShell Demo</title></head><body><h1>IIS Administration with PowerShell Demo</h1><p>Thank you for reading this post on how to administer IIS with PowerShell!</p><p>This page was created using the newer IISAdministration PowerShell module.</p><h2>First Steps</h2><p>Keep calm and learn PowerShell.</p></body></html>'
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
  #Setup-MyWebSite
  #Set Time Zone
  Set-TimeZone -id "Singapore Standard Time"
  
  Restart-Computer

</powershell>
EOF
}
