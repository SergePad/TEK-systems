# Task #1

# Creating IAM users
resource "aws_iam_user" "developer1" {
  name = "developer1"
}

resource "aws_iam_user" "developer2" {
  name = "developer2"
}

# Attach AWSCodeCommitFullAccess policy to developer1
resource "aws_iam_user_policy_attachment" "developer1_codecommit" {
  user       = aws_iam_user.developer1.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess"

  depends_on = [
    aws_iam_user.developer1
  ]
}

# Attach AWSCodeCommitFullAccess policy to developer2
resource "aws_iam_user_policy_attachment" "developer2_codecommit" {
  user       = aws_iam_user.developer2.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess"

  depends_on = [
    aws_iam_user.developer2
  ]
}

# Generate access keys for both users
resource "aws_iam_access_key" "developer1_key" {
  user = aws_iam_user.developer1.name
}

resource "aws_iam_access_key" "developer2_key" {
  user = aws_iam_user.developer2.name
}

#Output for generated key 

# Developer1

output "developer1_access_key" {
  value = aws_iam_access_key.developer1_key.id
}

output "developer1_secret_key" {
  value     = aws_iam_access_key.developer1_key.secret
  sensitive = true
}

#Developer2

output "developer2_access_key" {
  value = aws_iam_access_key.developer2_key.id
}

output "developer2_secret_key" {
  value     = aws_iam_access_key.developer2_key.secret
  sensitive = true
}

# Creatin IAM group

resource "aws_iam_group" "developers" {
  name = "Developers"
}

# Add users to the IAM group

resource "aws_iam_group_membership" "developers_membership" {
  name  = "developers-membership"
  group = aws_iam_group.developers.name

  users = [
    aws_iam_user.developer1.name,
    aws_iam_user.developer2.name,
  ]
}
# Attach the policy to the IAM group

resource "aws_iam_group_policy_attachment" "developers_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

#Task 2: Creating and Attaching Policies

# Custom IAM policy for S3 bucket

resource "aws_iam_policy" "s3_custom_policy" {
  name        = "S3_custom_policy"
  description = "Custom policy to grant read and write access to a specific S3 bucket"

  policy = file("s3_custom_policy.json")
}

# Attach the custom policy to the IAM group

resource "aws_iam_group_policy_attachment" "s3_custom_policy_attachment" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.s3_custom_policy.arn
}

#Task 3: Secrets Management

# Create the secret in AWS Secrets Manager

resource "aws_secretsmanager_secret" "rds_credentials" {
  name        = "RDS_Credentialss"
  description = "MySQL database credentials"
  #kms_key_id  = "alias/aws/secretsmanager" # uses aws managed key by default
}

# Define the secret version with the credentials
resource "aws_secretsmanager_secret_version" "rds_credentials_version" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id
  secret_string = jsonencode({
    username = "db_user"
    password = "db_password"
  })
}

# Define the custom IAM policy for Secrets Manager read-only access

resource "aws_iam_policy" "secrets_manager_read_only" {
  name        = "SecretsManagerReadOnly"
  description = "Policy to grant read-only access to Secrets Manager"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.rds_credentials.arn
      }
    ]
  })
}

# Attach the custom policy to the IAM group
resource "aws_iam_group_policy_attachment" "secrets_manager_read_only_attachment" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.secrets_manager_read_only.arn
}

#Task 4: Implementing RBAC

# Define the IAM role
resource "aws_iam_role" "ec2_instance_role" {
  name = "EC2InstanceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach the AmazonS3ReadOnlyAccess policy
resource "aws_iam_role_policy_attachment" "s3_read_only_access" {
  policy_arn = aws_iam_policy.s3_custom_policy.arn
  role       = aws_iam_role.ec2_instance_role.name
}

# Attach the SecretsManagerReadOnly policy
resource "aws_iam_role_policy_attachment" "secrets_manager_read_only" {
  policy_arn = aws_iam_policy.secrets_manager_read_only.arn
  role       = aws_iam_role.ec2_instance_role.name
}

# Assign Role to EC2 Instance:
#Data source to find the latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true

  owners = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Define the SSH key pair
resource "aws_key_pair" "key_pair" {
  key_name   = "tek-systems"
  public_key = file("~/.ssh/tek-systems.pub")
}

# Define the security group
resource "aws_security_group" "ec2_sg" {
  name        = "ec2-sg"
  description = "Allow SSH access"
  vpc_id      = "vpc-0bfc76481d34b4789"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Change it to company VPN
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # Allows all outbound traffic
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EC2 Security Group"
  }
}

# Define the IAM instance profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2InstanceProfile"
  role = aws_iam_role.ec2_instance_role.name
}

# Creating the EC2 instance
resource "aws_instance" "tek" {
  ami                  = data.aws_ami.amazon_linux_2.id
  instance_type        = "t2.micro"
  key_name             = aws_key_pair.key_pair.key_name
  security_groups      = [aws_security_group.ec2_sg.name]
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  tags = {
    Name = "TEK"
  }
}
