
# AWS Security Automation with Python & Boto3

## 📌 Overview
This project is an **AWS Security Automation framework** built with **Python and Boto3** to help **detect, enforce, and audit security best practices** across AWS accounts.

It is designed to reduce human error, enforce least privilege, and automate repetitive security operations such as:
- IAM security checks
- Logging and monitoring validation
- Encryption enforcement
- Compliance readiness

This repository demonstrates **real-world cloud security engineering skills**, not just exam knowledge.

---

## 🧱 Architecture Overview
The automation interacts with AWS services using **Boto3**, AWS’s official SDK for Python.

**Core AWS Services Used**
- AWS IAM
- AWS CloudTrail
- AWS CloudWatch
- AWS KMS
- Amazon S3
- AWS Config (optional)
- AWS Security Hub (optional)

Authentication is handled using **IAM roles or access keys**, following least-privilege best practices.

---

## 🚀 Features
✔ IAM security posture checks  
✔ Detection of overly permissive IAM policies  
✔ Validation of CloudTrail logging status  
✔ S3 bucket encryption and public access checks  
✔ KMS key usage validation  
✔ Automated security findings output  
✔ Modular Python structure for easy extension  

---

## 📂 Project Structure
```

aws-security-automation/
│
├── scripts/
│   ├── iam_audit.py
│   ├── cloudtrail_check.py
│   ├── s3_security_check.py
│   ├── kms_validation.py
│
├── utils/
│   ├── aws_session.py
│   ├── helpers.py
│
├── reports/
│   └── findings.json
│
├── requirements.txt
├── config.example.json
├── .gitignore
└── README.md

````

---

## 🛠 Prerequisites
Before running this project, ensure you have the following:

- **Python 3.9+**
- **AWS Account**
- **IAM user or role with security audit permissions**
- **AWS CLI configured**
- Basic understanding of AWS security concepts

---

## 🔐 Required IAM Permissions
It is strongly recommended to use **read-only security audit permissions**.

Minimum example policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "s3:GetBucket*",
        "kms:DescribeKey",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }
  ]
}
````

⚠️ **Do NOT use AdministratorAccess in production environments.**

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository

```bash
git https://github.com/Lakewest1/AWS-Security-Automation
cd aws-security-automation
```

---

### 2️⃣ Create and Activate Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Configure AWS Credentials

Use one of the following methods:

#### Option A: AWS CLI

```bash
aws configure
```

#### Option B: Environment Variables

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

#### Option C: IAM Role (Recommended)

Attach an IAM role to your EC2 instance or Lambda function.

---

## ▶️ Running the Automation

Run individual security checks:

```bash
python scripts/iam_audit.py
python scripts/cloudtrail_check.py
python scripts/s3_security_check.py
python scripts/kms_validation.py
```

Or run all checks:

```bash
python main.py
```

Findings will be saved to:

```
reports/findings.json
```

---

## 📊 Sample Output

```json
{
  "IAM": {
    "OverlyPermissivePolicies": ["AdminAccess"]
  },
  "CloudTrail": {
    "MultiRegionTrail": true,
    "LogFileValidation": true
  },
  "S3": {
    "PublicBuckets": ["example-bucket"]
  }
}
```

---

## 🔍 Security Best Practices Applied

* Least privilege IAM access
* No hardcoded credentials
* Modular design
* Read-only auditing by default
* Encrypted data handling
* Production-safe logging

---

## 📈 Roadmap / Future Improvements

* [ ] Lambda-based execution
* [ ] EventBridge scheduling
* [ ] Security Hub integration
* [ ] Config rule automation
* [ ] Slack / Email alerting
* [ ] Multi-account support

---

## 📚 Learning Outcomes

This project demonstrates:

* AWS Security architecture knowledge
* Python automation skills
* IAM policy analysis
* Cloud monitoring and logging understanding
* Real-world security tooling design

---

## ⚠️ Disclaimer

This tool is intended for **educational and internal security assessment purposes only**.
Always obtain proper authorization before running security checks in any AWS environment.

---

## 👤 Author  : Olalekan Musa (a.k.a Sir lakewest)

**Your Name**
Cloud Security Engineer | AWS | Python | Automation

---

## ⭐ Why This Project Matters

This project reflects **hands-on cloud security engineering**, not just certification knowledge.
It aligns directly with roles such as:

* Cloud Security Engineer
* SOC Analyst (Cloud)
* Security Automation Engineer
* AWS Solutions Architect (Security-focused)

