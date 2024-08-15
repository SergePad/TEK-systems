
# IAM Cloud Engineering Analyst Challenge
Task 1: Setting Up Identities
Creating IAM Users

We create two IAM users (developer1 and developer2):

Both users are provisioned using the aws_iam_user resource.

```
resource "aws_iam_user" "developer1" {
   name = "developer1"
}

resource "aws_iam_user" "developer2" {
  name = "developer2"
}
```
Screenshots:

![](../screenshots/Screenshot%202024-08-14%20at%206.08.31%20PM.png)

Attaching Policies to Users

We attach the AWSCodeCommitFullAccess policy to both developer1 and developer2.

![](../screenshots/Screenshot%202024-08-14%20at%206.44.34%20PM.png)

Generating Access Keys
Access keys are generated for both users (developer1 and developer2) to allow them to programmatically access AWS.

The access and secret keys are outputted for both users as sensitive information.

![](../screenshots/Screenshot%202024-08-14%20at%206.47.40%20PM.png)

After ```terraform apply``` outputs will look like:

![](../screenshots/Screenshot%202024-08-14%20at%206.48.56%20PM.png)

to recieve a secret key run 

```terraform state pull | jq '.resources[] | select(.type == "aws_iam_access_key") | .instances[0].attributes'```

![](../screenshots/Screenshot%202024-08-14%20at%206.51.19%20PM.png)

Creating an IAM Group and Attaching Policies

A group called Developers is created, and both users are added to this group.

![](../screenshots/Screenshot%202024-08-14%20at%206.53.51%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%206.57.00%20PM.png)

The AmazonEC2ReadOnlyAccess policy is attached to the Developers group.

![](../screenshots/Screenshot%202024-08-14%20at%206.54.51%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%206.56.12%20PM.png)

Task 2: Creating and Attaching Custom Policies
Creating a Custom S3 Policy

A custom policy, S3_custom_policy, grants read and write access to a specific S3 bucket.

The custom policy is loaded from the file s3_custom_policy.json

![](../screenshots/Screenshot%202024-08-14%20at%207.00.28%20PM.png)
The policy is then attached to the Developers group.

![](../screenshots/Screenshot%202024-08-14%20at%207.01.34%20PM.png)

Task 3: Secrets Management
Managing Secrets in AWS Secrets Manager

A secret named RDS_Credentials is created in AWS Secrets Manager to store database credentials.

A secret version is defined to hold the actual credentials (username and password)

![](../screenshots/Screenshot%202024-08-14%20at%207.03.59%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.05.25%20PM.png)

Creating a Custom IAM Policy for Secrets Manager
A custom policy, SecretsManagerReadOnly, is created to allow read-only access to the RDS_Credentials secret.
![](../screenshots/Screenshot%202024-08-14%20at%207.14.27%20PM.png)

The policy is then attached to the Developers group to allow users to read the secret

![](../screenshots/Screenshot%202024-08-14%20at%207.15.55%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.22.12%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.23.11%20PM.png)

Task 4: Implementing Role-Based Access Control (RBAC)

Creating an IAM Role for EC2
An IAM role, EC2InstanceRole, is created to grant the EC2 instance permission to assume the role
![](../screenshots/Screenshot%202024-08-14%20at%207.25.33%20PM.png)

Attaching Policies to the EC2 IAM Role
AmazonS3ReadOnlyAccess and the custom SecretsManagerReadOnly policies are attached to the IAM role

![](../screenshots/Screenshot%202024-08-14%20at%207.27.10%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.27.50%20PM.png)

Task 5: Provisioning EC2 Instance
Defining AMI, Key Pair, and Security Group

The latest Amazon Linux 2 AMI is fetched using the aws_ami data source.

An SSH key pair is created to access the EC2 instance.

A security group named ec2-sg is created to allow inbound SSH access on port 22
![](../screenshots/Screenshot%202024-08-14%20at%207.29.54%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.30.09%20PM.png)

Defining IAM Instance Profile

The EC2InstanceRole is attached to an instance profile to be used by the EC2 instance

![](../screenshots/Screenshot%202024-08-14%20at%207.32.07%20PM.png)

Creating the EC2 Instance
An EC2 instance is provisioned using the fetched Amazon Linux 2 AMI, with the specified security group, key pair, and instance profile
![](../screenshots/Screenshot%202024-08-14%20at%207.34.00%20PM.png)
![](../screenshots/Screenshot%202024-08-14%20at%207.35.05%20PM.png)

Task 5: Testing and Validation

Verifying that the EC2 instance can access both my-app-bucket and RDS_Credentials
![](../screenshots/Screenshot%202024-08-14%20at%207.37.19%20PM.png)

Verifying that developer1 can list and read objects from my-app-bucket and can read the RDS_Credentials secret

![](../screenshots/Screenshot%202024-08-14%20at%207.39.43%20PM.png)

Verifying that developer2 can list and read objects from my-app-bucket and can read the RDS_Credentials secret
![](../screenshots/Screenshot%202024-08-14%20at%208.01.07%20PM.png)

Task 6: Authentication & Authorization

![](../screenshots/Screenshot%202024-08-14%20at%208.02.45%20PM.png)

1. A client first log in via Cognito

2. After successful login, Cognito returns an id_token to the client

3. The client sends a request to the API Gateway with the received id_token

4. The API Gateway verifies in Cognito whether the id_token is valid

5. Cognito will return to API Gateway a success response when the id_token is valid

6. The API Gateway sends the request to the lambda function

7. The lambda function executes and sends its response to the API Gateway

8. The API Gateway sends the response to the client
