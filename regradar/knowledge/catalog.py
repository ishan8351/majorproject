"""
Ontological Regulatory Catalog for RegRadar.

Comprehensive catalog of standards, controls, technical requirements, cloud resources,
and non-destructive remediation rules across HIPAA, GDPR, NIST SP 800-53, and PCI-DSS
for AWS and Azure infrastructure.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from regradar.knowledge.models import (
    CloudResourceNode,
    ControlNode,
    RemediationRule,
    RequirementNode,
    StandardNode,
)
from regradar.remediation.models import RemediationStrategy


# ---------------------------------------------------------------------------
# 1. Statutory Standards
# ---------------------------------------------------------------------------
STANDARDS: Dict[str, StandardNode] = {
    "HIPAA": StandardNode(
        id="HIPAA",
        name="Health Insurance Portability and Accountability Act",
        description="US federal law establishing national standards for safeguarding protected health information (PHI) under the HIPAA Security Rule (45 CFR Part 160 & Part 164).",
        version="45 CFR Part 160/164",
        jurisdiction="US Healthcare",
    ),
    "GDPR": StandardNode(
        id="GDPR",
        name="General Data Protection Regulation",
        description="European Union regulation on data privacy and security for all individuals within the EU/EEA (Regulation (EU) 2016/679).",
        version="Regulation (EU) 2016/679",
        jurisdiction="European Union",
    ),
    "NIST_SP_800_53": StandardNode(
        id="NIST_SP_800_53",
        name="NIST SP 800-53",
        description="National Institute of Standards and Technology Special Publication 800-53: Security and Privacy Controls for Information Systems and Organizations.",
        version="Rev. 5",
        jurisdiction="US Federal / Global Enterprise",
    ),
    "PCI_DSS": StandardNode(
        id="PCI_DSS",
        name="Payment Card Industry Data Security Standard",
        description="Global information security standard administered by the PCI SSC to secure cardholder data (CHD) and cardholder data environments (CDE).",
        version="v4.0",
        jurisdiction="Global Payment Card Industry",
    ),
}


# ---------------------------------------------------------------------------
# 2. Specific Regulatory Controls / Statutes
# ---------------------------------------------------------------------------
CONTROLS: Dict[str, ControlNode] = {
    # HIPAA Controls
    "HIPAA_164_312_a_2_iv": ControlNode(
        id="HIPAA_164_312_a_2_iv",
        control_id="§164.312(a)(2)(iv)",
        standard_id="HIPAA",
        title="Encryption and Decryption",
        description="Implement a mechanism to encrypt and decrypt electronic protected health information (ePHI) at rest and in storage.",
        family="Technical Safeguards",
    ),
    "HIPAA_164_308_a_7_ii_A": ControlNode(
        id="HIPAA_164_308_a_7_ii_A",
        control_id="§164.308(a)(7)(ii)(A)",
        standard_id="HIPAA",
        title="Data Backup Plan",
        description="Establish and implement procedures to create and maintain retrievable exact copies of electronic protected health information.",
        family="Administrative Safeguards",
    ),
    "HIPAA_164_308_a_7_ii_B": ControlNode(
        id="HIPAA_164_308_a_7_ii_B",
        control_id="§164.308(a)(7)(ii)(B)",
        standard_id="HIPAA",
        title="Disaster Recovery Plan",
        description="Establish and implement procedures to restore any loss of data in the event of an emergency or system disruption.",
        family="Administrative Safeguards",
    ),
    "HIPAA_164_312_b": ControlNode(
        id="HIPAA_164_312_b",
        control_id="§164.312(b)",
        standard_id="HIPAA",
        title="Audit Controls",
        description="Implement hardware, software, and procedural mechanisms that record and examine activity in information systems containing ePHI.",
        family="Technical Safeguards",
    ),
    "HIPAA_164_312_e_1": ControlNode(
        id="HIPAA_164_312_e_1",
        control_id="§164.312(e)(1)",
        standard_id="HIPAA",
        title="Transmission Security",
        description="Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic communications networks.",
        family="Technical Safeguards",
    ),
    "HIPAA_164_308_a_5_ii_D": ControlNode(
        id="HIPAA_164_308_a_5_ii_D",
        control_id="§164.308(a)(5)(ii)(D)",
        standard_id="HIPAA",
        title="Password Management",
        description="Implement procedures for creating, changing, and safeguarding authenticators and passwords.",
        family="Administrative Safeguards",
    ),

    # GDPR Controls
    "GDPR_Art_32_1_a": ControlNode(
        id="GDPR_Art_32_1_a",
        control_id="Art. 32(1)(a)",
        standard_id="GDPR",
        title="Pseudonymisation and Encryption of Personal Data",
        description="Implement appropriate technical measures including pseudonymisation and encryption to ensure security appropriate to the risk.",
        family="Security of Processing",
    ),
    "GDPR_Art_32_1_b": ControlNode(
        id="GDPR_Art_32_1_b",
        control_id="Art. 32(1)(b)",
        standard_id="GDPR",
        title="Confidentiality, Integrity, and Resilience",
        description="Ensure the ongoing confidentiality, integrity, availability, and resilience of processing systems and services.",
        family="Security of Processing",
    ),
    "GDPR_Art_32_1_c": ControlNode(
        id="GDPR_Art_32_1_c",
        control_id="Art. 32(1)(c)",
        standard_id="GDPR",
        title="Restoration of Availability and Access",
        description="Ensure the ability to restore the availability and access to personal data in a timely manner in the event of an incident.",
        family="Security of Processing",
    ),
    "GDPR_Art_25": ControlNode(
        id="GDPR_Art_25",
        control_id="Art. 25",
        standard_id="GDPR",
        title="Data Protection by Design and Default",
        description="Implement appropriate technical and organizational measures designed to implement data-protection principles effectively.",
        family="Principles",
    ),

    # NIST SP 800-53 Controls
    "NIST_AC_3": ControlNode(
        id="NIST_AC_3",
        control_id="AC-3",
        standard_id="NIST_SP_800_53",
        title="Access Enforcement",
        description="Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
        family="Access Control",
    ),
    "NIST_AC_4": ControlNode(
        id="NIST_AC_4",
        control_id="AC-4",
        standard_id="NIST_SP_800_53",
        title="Information Flow Enforcement",
        description="Enforce approved authorizations for controlling the flow of information within the system and between interconnected systems.",
        family="Access Control",
    ),
    "NIST_AC_6": ControlNode(
        id="NIST_AC_6",
        control_id="AC-6",
        standard_id="NIST_SP_800_53",
        title="Least Privilege",
        description="Employ the principle of least privilege, allowing only authorized accesses for users and processes necessary to accomplish assigned tasks.",
        family="Access Control",
    ),
    "NIST_AU_2": ControlNode(
        id="NIST_AU_2",
        control_id="AU-2",
        standard_id="NIST_SP_800_53",
        title="Event Logging",
        description="Identify and record events on the system that are significant and relevant to the security of information.",
        family="Audit and Accountability",
    ),
    "NIST_AU_3": ControlNode(
        id="NIST_AU_3",
        control_id="AU-3",
        standard_id="NIST_SP_800_53",
        title="Content of Audit Records",
        description="Ensure audit records contain information establishing what type of event occurred, when, where, the source, and outcome.",
        family="Audit and Accountability",
    ),
    "NIST_AU_6": ControlNode(
        id="NIST_AU_6",
        control_id="AU-6",
        standard_id="NIST_SP_800_53",
        title="Audit Record Review, Analysis, and Reporting",
        description="Review and analyze system audit records for indications of unusual or suspicious activity and report findings.",
        family="Audit and Accountability",
    ),
    "NIST_AU_9": ControlNode(
        id="NIST_AU_9",
        control_id="AU-9",
        standard_id="NIST_SP_800_53",
        title="Protection of Audit Information",
        description="Protect audit information and audit tools from unauthorized access, modification, and deletion.",
        family="Audit and Accountability",
    ),
    "NIST_CP_2": ControlNode(
        id="NIST_CP_2",
        control_id="CP-2",
        standard_id="NIST_SP_800_53",
        title="Contingency Plan",
        description="Develop, review, and maintain a contingency plan addressing system restoration without compromising security.",
        family="Contingency Planning",
    ),
    "NIST_CP_9": ControlNode(
        id="NIST_CP_9",
        control_id="CP-9",
        standard_id="NIST_SP_800_53",
        title="Information System Backup",
        description="Conduct backups of user-level and system-level information including security-related documentation.",
        family="Contingency Planning",
    ),
    "NIST_IA_2": ControlNode(
        id="NIST_IA_2",
        control_id="IA-2",
        standard_id="NIST_SP_800_53",
        title="Identification and Authentication",
        description="Uniquely identify and authenticate organizational users and processes acting on behalf of organizational users.",
        family="Identification and Authentication",
    ),
    "NIST_IA_5": ControlNode(
        id="NIST_IA_5",
        control_id="IA-5",
        standard_id="NIST_SP_800_53",
        title="Authenticator Management",
        description="Manage system authenticators including passwords, tokens, certificates, and biometrics with strict complexity.",
        family="Identification and Authentication",
    ),
    "NIST_SC_8": ControlNode(
        id="NIST_SC_8",
        control_id="SC-8",
        standard_id="NIST_SP_800_53",
        title="Transmission Confidentiality and Integrity",
        description="Protect the confidentiality and integrity of transmitted information using cryptographic mechanisms.",
        family="System and Communications Protection",
    ),
    "NIST_SC_12": ControlNode(
        id="NIST_SC_12",
        control_id="SC-12",
        standard_id="NIST_SP_800_53",
        title="Cryptographic Key Establishment and Management",
        description="Establish and manage cryptographic keys when cryptography is required and employed within the system.",
        family="System and Communications Protection",
    ),
    "NIST_SC_13": ControlNode(
        id="NIST_SC_13",
        control_id="SC-13",
        standard_id="NIST_SP_800_53",
        title="Cryptographic Protection",
        description="Employ cryptographic modules in accordance with applicable federal laws, policies, and directives.",
        family="System and Communications Protection",
    ),

    # PCI-DSS Controls
    "PCI_DSS_1_2": ControlNode(
        id="PCI_DSS_1_2",
        control_id="Req 1.2",
        standard_id="PCI_DSS",
        title="Network Security Controls Configuration",
        description="Build and maintain secure network configurations to restrict inbound and outbound traffic.",
        family="Network Security",
    ),
    "PCI_DSS_1_3": ControlNode(
        id="PCI_DSS_1_3",
        control_id="Req 1.3",
        standard_id="PCI_DSS",
        title="Restricted Public Access",
        description="Prohibit direct public internet access between the internet and any system component in the cardholder data environment.",
        family="Network Security",
    ),
    "PCI_DSS_3_4": ControlNode(
        id="PCI_DSS_3_4",
        control_id="Req 3.4",
        standard_id="PCI_DSS",
        title="Protect Cardholder Data with Strong Cryptography",
        description="Render primary account numbers (PAN) unreadable anywhere they are stored using strong cryptographic algorithms.",
        family="Cardholder Data Protection",
    ),
    "PCI_DSS_3_5": ControlNode(
        id="PCI_DSS_3_5",
        control_id="Req 3.5",
        standard_id="PCI_DSS",
        title="Cryptographic Key Protection",
        description="Protect cryptographic keys used to encrypt cardholder data against disclosure and misuse.",
        family="Cardholder Data Protection",
    ),
    "PCI_DSS_3_6": ControlNode(
        id="PCI_DSS_3_6",
        control_id="Req 3.6",
        standard_id="PCI_DSS",
        title="Cryptographic Key Management",
        description="Fully document and implement all key management processes and procedures for cryptographic keys used for PAN encryption.",
        family="Cardholder Data Protection",
    ),
    "PCI_DSS_4_1": ControlNode(
        id="PCI_DSS_4_1",
        control_id="Req 4.1",
        standard_id="PCI_DSS",
        title="Safeguard PAN During Transmission",
        description="Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open networks.",
        family="Cardholder Data Protection",
    ),
    "PCI_DSS_7_1": ControlNode(
        id="PCI_DSS_7_1",
        control_id="Req 7.1",
        standard_id="PCI_DSS",
        title="Access Limitation to Need-to-Know",
        description="Limit access to system components and cardholder data to only those individuals whose jobs require such access.",
        family="Access Control",
    ),
    "PCI_DSS_7_2": ControlNode(
        id="PCI_DSS_7_2",
        control_id="Req 7.2",
        standard_id="PCI_DSS",
        title="Establish Access Control Systems",
        description="Establish an access control system for system components that restricts access based on user need-to-know.",
        family="Access Control",
    ),
    "PCI_DSS_8_2": ControlNode(
        id="PCI_DSS_8_2",
        control_id="Req 8.2",
        standard_id="PCI_DSS",
        title="Strong Authenticator Management",
        description="Ensure user identification and authentication management enforces complex passwords and credential lifecycle policies.",
        family="Identification and Authentication",
    ),
    "PCI_DSS_8_3": ControlNode(
        id="PCI_DSS_8_3",
        control_id="Req 8.3",
        standard_id="PCI_DSS",
        title="Multi-Factor Authentication (MFA)",
        description="Mandate and enforce multi-factor authentication for all access into the cardholder data environment.",
        family="Identification and Authentication",
    ),
    "PCI_DSS_10_1": ControlNode(
        id="PCI_DSS_10_1",
        control_id="Req 10.1",
        standard_id="PCI_DSS",
        title="Audit Trail Logging",
        description="Implement audit trails to link all access to system components to each individual user.",
        family="Audit and Monitoring",
    ),
    "PCI_DSS_10_2": ControlNode(
        id="PCI_DSS_10_2",
        control_id="Req 10.2",
        standard_id="PCI_DSS",
        title="Automated Privileged Audit Trails",
        description="Implement automated audit trails for all system components to reconstruct events including privileged user actions.",
        family="Audit and Monitoring",
    ),
    "PCI_DSS_10_3": ControlNode(
        id="PCI_DSS_10_3",
        control_id="Req 10.3",
        standard_id="PCI_DSS",
        title="Audit Trail Content",
        description="Record user identification, type of event, date and time, success/failure indication, and identity of affected data.",
        family="Audit and Monitoring",
    ),
    "PCI_DSS_10_5": ControlNode(
        id="PCI_DSS_10_5",
        control_id="Req 10.5",
        standard_id="PCI_DSS",
        title="Secure Audit Trails",
        description="Secure audit trails so that they cannot be altered or deleted.",
        family="Audit and Monitoring",
    ),
}


# ---------------------------------------------------------------------------
# 3. Security Requirements
# ---------------------------------------------------------------------------
REQUIREMENTS: Dict[str, RequirementNode] = {
    "REQ_ENCRYPTION_AT_REST": RequirementNode(
        id="REQ_ENCRYPTION_AT_REST",
        name="Encryption at Rest",
        description="Enforce strong symmetric (e.g. AES-256) or customer-managed key encryption for all stored, persistent cloud data.",
        category="Data Protection",
    ),
    "REQ_ENCRYPTION_IN_TRANSIT": RequirementNode(
        id="REQ_ENCRYPTION_IN_TRANSIT",
        name="Encryption in Transit",
        description="Enforce modern TLS (v1.2+) and secure encrypted protocols for all network communications and ingress endpoints.",
        category="Network Security",
    ),
    "REQ_ZERO_PUBLIC_INGRESS": RequirementNode(
        id="REQ_ZERO_PUBLIC_INGRESS",
        name="Zero Public Ingress",
        description="Prohibit unrestricted direct public ingress from 0.0.0.0/0 to sensitive storage, databases, and management ports (SSH 22, RDP 3389).",
        category="Network Security",
    ),
    "REQ_AUDIT_LOGGING": RequirementNode(
        id="REQ_AUDIT_LOGGING",
        name="Audit Logging",
        description="Enforce comprehensive, centralized, and tamper-resistant event logging, flow logs, and performance metric tracking.",
        category="Audit and Accountability",
    ),
    "REQ_BACKUP_AND_RESILIENCE": RequirementNode(
        id="REQ_BACKUP_AND_RESILIENCE",
        name="Backup and Disaster Recovery",
        description="Mandate automated point-in-time recovery, multi-AZ high availability deployment, and object versioning for disaster resilience.",
        category="Resilience",
    ),
    "REQ_LEAST_PRIVILEGE": RequirementNode(
        id="REQ_LEAST_PRIVILEGE",
        name="Least Privilege and Identity Management",
        description="Restrict wildcard admin access, enforce strong password policies, mandate MFA, and enforce IMDSv2 token authentication.",
        category="Identity and Access Management",
    ),
    "REQ_KEY_MANAGEMENT": RequirementNode(
        id="REQ_KEY_MANAGEMENT",
        name="Cryptographic Key Management",
        description="Enforce automated key rotation and strictly bounded IAM access policies on cryptographic master keys.",
        category="Cryptography",
    ),
    "REQ_SYSTEM_INTEGRITY": RequirementNode(
        id="REQ_SYSTEM_INTEGRITY",
        name="System and Storage Integrity",
        description="Enforce dedicated persistent EBS throughput optimization and cryptographic log file integrity validation.",
        category="System Integrity",
    ),
}


# ---------------------------------------------------------------------------
# 4. Cloud Infrastructure Resources
# ---------------------------------------------------------------------------
CLOUD_RESOURCES: Dict[str, CloudResourceNode] = {
    # AWS
    "aws_s3_bucket": CloudResourceNode(
        id="aws_s3_bucket",
        resource_type="aws_s3_bucket",
        cloud_provider="aws",
        service="s3",
        description="AWS Simple Storage Service (S3) bucket for object storage.",
    ),
    "aws_db_instance": CloudResourceNode(
        id="aws_db_instance",
        resource_type="aws_db_instance",
        cloud_provider="aws",
        service="rds",
        description="AWS Relational Database Service (RDS) instance.",
    ),
    "aws_iam_policy": CloudResourceNode(
        id="aws_iam_policy",
        resource_type="aws_iam_policy",
        cloud_provider="aws",
        service="iam",
        description="AWS Identity and Access Management policy document.",
    ),
    "aws_iam_account_password_policy": CloudResourceNode(
        id="aws_iam_account_password_policy",
        resource_type="aws_iam_account_password_policy",
        cloud_provider="aws",
        service="iam",
        description="AWS Account-wide IAM password policy configuration.",
    ),
    "aws_kms_key": CloudResourceNode(
        id="aws_kms_key",
        resource_type="aws_kms_key",
        cloud_provider="aws",
        service="kms",
        description="AWS Key Management Service customer managed key.",
    ),
    "aws_cloudtrail": CloudResourceNode(
        id="aws_cloudtrail",
        resource_type="aws_cloudtrail",
        cloud_provider="aws",
        service="cloudtrail",
        description="AWS CloudTrail service for event auditing and API tracking.",
    ),
    "aws_security_group": CloudResourceNode(
        id="aws_security_group",
        resource_type="aws_security_group",
        cloud_provider="aws",
        service="vpc",
        description="AWS VPC Virtual Security Group firewall for compute resources.",
    ),
    "aws_instance": CloudResourceNode(
        id="aws_instance",
        resource_type="aws_instance",
        cloud_provider="aws",
        service="ec2",
        description="AWS Elastic Compute Cloud (EC2) virtual machine instance.",
    ),
    "aws_vpc": CloudResourceNode(
        id="aws_vpc",
        resource_type="aws_vpc",
        cloud_provider="aws",
        service="vpc",
        description="AWS Virtual Private Cloud network boundary.",
    ),

    # Azure
    "azurerm_storage_account": CloudResourceNode(
        id="azurerm_storage_account",
        resource_type="azurerm_storage_account",
        cloud_provider="azure",
        service="storage",
        description="Microsoft Azure Storage Account for blobs, files, and tables.",
    ),
    "azurerm_network_security_group": CloudResourceNode(
        id="azurerm_network_security_group",
        resource_type="azurerm_network_security_group",
        cloud_provider="azure",
        service="nsg",
        description="Microsoft Azure Network Security Group firewall filter.",
    ),
    "google_compute_network": CloudResourceNode(
        id="google_compute_network",
        resource_type="google_compute_network",
        cloud_provider="gcp",
        service="compute",
        description="Google Cloud Platform Virtual Private Cloud network.",
    ),
    "google_compute_firewall": CloudResourceNode(
        id="google_compute_firewall",
        resource_type="google_compute_firewall",
        cloud_provider="gcp",
        service="compute",
        description="Google Cloud Platform Compute Engine firewall rule.",
    ),
    "google_storage_bucket": CloudResourceNode(
        id="google_storage_bucket",
        resource_type="google_storage_bucket",
        cloud_provider="gcp",
        service="storage",
        description="Google Cloud Platform Cloud Storage bucket.",
    ),
}


# ---------------------------------------------------------------------------
# 5. Remediation Rules (25+ real-world compliance rules across AWS & Azure)
# ---------------------------------------------------------------------------
RULES: Dict[str, RemediationRule] = {
    # 1. AWS S3 Default SSE AES-256 Encryption
    "CKV_AWS_19": RemediationRule(
        check_id="CKV_AWS_19",
        name="S3 Server-Side Encryption",
        description="Enforce default AES-256 server-side encryption via additive attachment.",
        resource_type="aws_s3_bucket",
        framework="HIPAA",
        statute_reference="HIPAA §164.312(a)(2)(iv) & GDPR Art. 32(1)(a)",
        control_ids=["HIPAA_164_312_a_2_iv", "GDPR_Art_32_1_a", "PCI_DSS_3_4", "NIST_SC_13"],
        requirement_id="REQ_ENCRYPTION_AT_REST",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_encryption" {{
  bucket = {resource_id}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
""",
        validation_rules=["require_sse_algorithm_aes256", "prevent_destructive_bucket_recreation"],
    ),

    # 2. AWS S3 Object Versioning
    "CKV_AWS_21": RemediationRule(
        check_id="CKV_AWS_21",
        name="S3 Object Versioning",
        description="Enforce immutable object versioning for data recovery.",
        resource_type="aws_s3_bucket",
        framework="HIPAA",
        statute_reference="HIPAA §164.308(a)(7)(ii)(A) & GDPR Art. 32(1)(c)",
        control_ids=["HIPAA_164_308_a_7_ii_A", "GDPR_Art_32_1_c", "NIST_CP_9"],
        requirement_id="REQ_BACKUP_AND_RESILIENCE",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_s3_bucket_versioning" "{name}_versioning" {{
  bucket = {resource_id}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
""",
        validation_rules=["require_status_enabled", "zero_destruction_guarantee"],
    ),

    # 3. AWS S3 Universal Public Access Block
    "CKV_AWS_53": RemediationRule(
        check_id="CKV_AWS_53",
        name="S3 Public Access Block",
        description="Enforce universal public access block on cloud storage.",
        resource_type="aws_s3_bucket",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AC-3 / AC-4 & GDPR Art. 32",
        control_ids=["NIST_AC_3", "NIST_AC_4", "GDPR_Art_32_1_b", "PCI_DSS_1_3"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_s3_bucket_public_access_block" "{name}_public_block" {{
  bucket = {resource_id}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
""",
        validation_rules=["enforce_all_four_block_flags"],
    ),

    # 4. AWS EC2 IMDSv2 Token Enforcement
    "CKV_AWS_79": RemediationRule(
        check_id="CKV_AWS_79",
        name="EC2 IMDSv2 Enforcement",
        description="Mandate IMDSv2 token-based authentication to prevent SSRF credential theft.",
        resource_type="aws_instance",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 SC-8 / IA-2",
        control_ids=["NIST_SC_8", "NIST_IA_2"],
        requirement_id="REQ_LEAST_PRIVILEGE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="metadata_options",
        attribute_value="""  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }""",
        validation_rules=["require_http_tokens_required"],
    ),

    # 5. AWS EC2 EBS Optimization
    "CKV_AWS_135": RemediationRule(
        check_id="CKV_AWS_135",
        name="EC2 EBS Optimization",
        description="Enable dedicated EBS throughput for persistent I/O integrity.",
        resource_type="aws_instance",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 CP-2 (Contingency Plan)",
        control_ids=["NIST_CP_2"],
        requirement_id="REQ_SYSTEM_INTEGRITY",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="ebs_optimized",
        attribute_value="  ebs_optimized = true",
        validation_rules=["ensure_ebs_optimized_true"],
    ),

    # 6. AWS Security Group Audit Description
    "CKV_AWS_23": RemediationRule(
        check_id="CKV_AWS_23",
        name="Security Group Description",
        description="Enforce security policy audit descriptions on firewalls.",
        resource_type="aws_security_group",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AC-4 / AU-3",
        control_ids=["NIST_AC_4", "NIST_AU_3"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="description",
        attribute_value='  description = "RegRadar managed: TLS ingress restricted to secure endpoints"',
        validation_rules=["non_empty_description"],
    ),

    # 7. AWS S3 Server Access Logging
    "CKV_AWS_18": RemediationRule(
        check_id="CKV_AWS_18",
        name="S3 Access Logging",
        description="Enforce centralized audit access logging for S3 bucket requests.",
        resource_type="aws_s3_bucket",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AU-2 / AU-3 & HIPAA §164.312(b)",
        control_ids=["NIST_AU_2", "NIST_AU_3", "HIPAA_164_312_b", "PCI_DSS_10_1"],
        requirement_id="REQ_AUDIT_LOGGING",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_s3_bucket_logging" "{name}_logging" {{
  bucket        = {resource_id}.id
  target_bucket = "audit-logs-central"
  target_prefix = "s3-access-logs/{name}/"
}}
""",
        validation_rules=["ensure_target_bucket_defined"],
    ),

    # 8. AWS S3 KMS CMK Encryption
    "CKV_AWS_145": RemediationRule(
        check_id="CKV_AWS_145",
        name="S3 KMS CMK Encryption",
        description="Enforce S3 bucket encryption with customer managed KMS keys (CMK).",
        resource_type="aws_s3_bucket",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 3.4 / 3.5 & NIST SP 800-53 SC-13",
        control_ids=["PCI_DSS_3_4", "PCI_DSS_3_5", "NIST_SC_13", "HIPAA_164_312_a_2_iv"],
        requirement_id="REQ_ENCRYPTION_AT_REST",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_s3_bucket_server_side_encryption_configuration" "{name}_kms_encryption" {{
  bucket = {resource_id}.id

  rule {{
    apply_server_side_encryption_by_default {{
      kms_master_key_id = "aws_kms_key.default.arn"
      sse_algorithm     = "aws:kms"
    }}
  }}
}}
""",
        validation_rules=["require_sse_algorithm_aws_kms"],
    ),

    # 9. AWS S3 Block Public Policy
    "CKV_AWS_54": RemediationRule(
        check_id="CKV_AWS_54",
        name="S3 Block Public Policy",
        description="Ensure S3 block public policy is enabled to prevent public bucket policies.",
        resource_type="aws_s3_bucket",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.3 & NIST SP 800-53 AC-3",
        control_ids=["PCI_DSS_1_3", "NIST_AC_3"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="block_public_policy",
        attribute_value="  block_public_policy = true",
        validation_rules=["block_public_policy_true"],
    ),

    # 10. AWS S3 Ignore Public ACLs
    "CKV_AWS_55": RemediationRule(
        check_id="CKV_AWS_55",
        name="S3 Ignore Public ACLs",
        description="Ensure S3 bucket ignores public ACLs, preventing public permissions grant.",
        resource_type="aws_s3_bucket",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.3 & NIST SP 800-53 AC-3",
        control_ids=["PCI_DSS_1_3", "NIST_AC_3"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="ignore_public_acls",
        attribute_value="  ignore_public_acls = true",
        validation_rules=["ignore_public_acls_true"],
    ),

    # 11. AWS S3 Restrict Public Buckets
    "CKV_AWS_56": RemediationRule(
        check_id="CKV_AWS_56",
        name="S3 Restrict Public Buckets",
        description="Restrict bucket access to authorized users and AWS service principals.",
        resource_type="aws_s3_bucket",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.3 & NIST SP 800-53 AC-3",
        control_ids=["PCI_DSS_1_3", "NIST_AC_3"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="restrict_public_buckets",
        attribute_value="  restrict_public_buckets = true",
        validation_rules=["restrict_public_buckets_true"],
    ),

    # 12. AWS RDS Storage Encryption at Rest
    "CKV_AWS_16": RemediationRule(
        check_id="CKV_AWS_16",
        name="RDS Storage Encryption",
        description="Enforce cryptographic storage encryption at rest for relational databases.",
        resource_type="aws_db_instance",
        framework="HIPAA",
        statute_reference="HIPAA §164.312(a)(2)(iv) & PCI-DSS 3.4 & NIST SC-13",
        control_ids=["HIPAA_164_312_a_2_iv", "PCI_DSS_3_4", "NIST_SC_13", "GDPR_Art_32_1_a"],
        requirement_id="REQ_ENCRYPTION_AT_REST",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="storage_encrypted",
        attribute_value="  storage_encrypted = true",
        validation_rules=["storage_encrypted_true"],
    ),

    # 13. AWS RDS Multi-AZ High Availability
    "CKV_AWS_157": RemediationRule(
        check_id="CKV_AWS_157",
        name="RDS Multi-AZ Deployment",
        description="Ensure RDS databases run in Multi-AZ configuration for disaster recovery and failover.",
        resource_type="aws_db_instance",
        framework="HIPAA",
        statute_reference="HIPAA §164.308(a)(7)(ii)(B) & GDPR Art. 32(1)(b) & NIST CP-2",
        control_ids=["HIPAA_164_308_a_7_ii_B", "GDPR_Art_32_1_b", "NIST_CP_2"],
        requirement_id="REQ_BACKUP_AND_RESILIENCE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="multi_az",
        attribute_value="  multi_az = true",
        validation_rules=["multi_az_true"],
    ),

    # 14. AWS RDS Backup Retention Period
    "CKV_AWS_17": RemediationRule(
        check_id="CKV_AWS_17",
        name="RDS Backup Retention",
        description="Ensure automated database backup retention is set to at least 7 days for recovery.",
        resource_type="aws_db_instance",
        framework="HIPAA",
        statute_reference="HIPAA §164.308(a)(7)(ii)(A) & GDPR Art. 32(1)(c) & NIST CP-9",
        control_ids=["HIPAA_164_308_a_7_ii_A", "GDPR_Art_32_1_c", "NIST_CP_9"],
        requirement_id="REQ_BACKUP_AND_RESILIENCE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="backup_retention_period",
        attribute_value="  backup_retention_period = 7",
        validation_rules=["backup_retention_gte_7"],
    ),

    # 15. AWS RDS Enhanced Monitoring
    "CKV_AWS_118": RemediationRule(
        check_id="CKV_AWS_118",
        name="RDS Enhanced Monitoring",
        description="Enable real-time OS metric tracking and monitoring interval on RDS instances.",
        resource_type="aws_db_instance",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AU-6 & PCI-DSS 10.2",
        control_ids=["NIST_AU_6", "PCI_DSS_10_2"],
        requirement_id="REQ_AUDIT_LOGGING",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="monitoring_interval",
        attribute_value="  monitoring_interval = 60",
        validation_rules=["monitoring_interval_positive"],
    ),

    # 16. AWS IAM Policy Wildcard Privilege Restriction
    "CKV_AWS_40": RemediationRule(
        check_id="CKV_AWS_40",
        name="IAM Least Privilege Wildcard Restriction",
        description="Prohibit full administrative wildcard privileges (*:*) in IAM access policies.",
        resource_type="aws_iam_policy",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AC-6 & PCI-DSS 7.1",
        control_ids=["NIST_AC_6", "PCI_DSS_7_1", "PCI_DSS_7_2"],
        requirement_id="REQ_LEAST_PRIVILEGE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="policy",
        attribute_value="""  # RegRadar: Enforce least-privilege specific action grants""",
        validation_rules=["disallow_wildcard_admin_actions"],
    ),

    # 17. AWS IAM Password Policy Complexity
    "CKV_AWS_60": RemediationRule(
        check_id="CKV_AWS_60",
        name="IAM Password Complexity Policy",
        description="Enforce strong password policy requirements (14+ characters, numbers, uppercase, symbols).",
        resource_type="aws_iam_account_password_policy",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 IA-5 & PCI-DSS 8.2 & HIPAA §164.308(a)(5)(ii)(D)",
        control_ids=["NIST_IA_5", "PCI_DSS_8_2", "HIPAA_164_308_a_5_ii_D"],
        requirement_id="REQ_LEAST_PRIVILEGE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="minimum_password_length",
        attribute_value="""  minimum_password_length        = 14
  require_symbols                = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true""",
        validation_rules=["length_gte_14", "symbols_required"],
    ),

    # 18. AWS IAM MFA Enforcement
    "CKV_AWS_109": RemediationRule(
        check_id="CKV_AWS_109",
        name="IAM MFA Enforcement",
        description="Require multi-factor authentication condition for privileged administrative access.",
        resource_type="aws_iam_policy",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 8.3 & NIST SP 800-53 IA-2",
        control_ids=["PCI_DSS_8_3", "NIST_IA_2"],
        requirement_id="REQ_LEAST_PRIVILEGE",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="policy",
        attribute_value="""  # RegRadar: Condition aws:MultiFactorAuthPresent = true""",
        validation_rules=["require_mfa_condition"],
    ),

    # 19. AWS KMS Key Rotation
    "CKV_AWS_7": RemediationRule(
        check_id="CKV_AWS_7",
        name="KMS Key Rotation",
        description="Enforce annual automatic key rotation for customer-managed KMS keys.",
        resource_type="aws_kms_key",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 3.6 & NIST SP 800-53 SC-12 & HIPAA §164.312(a)(2)(iv)",
        control_ids=["PCI_DSS_3_6", "NIST_SC_12", "HIPAA_164_312_a_2_iv"],
        requirement_id="REQ_KEY_MANAGEMENT",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="enable_key_rotation",
        attribute_value="  enable_key_rotation = true",
        validation_rules=["enable_key_rotation_true"],
    ),

    # 20. AWS KMS Key Policy Principal Limitation
    "CKV_AWS_33": RemediationRule(
        check_id="CKV_AWS_33",
        name="KMS Key Policy Least Privilege",
        description="Prevent wildcard root principal access in KMS customer key policies.",
        resource_type="aws_kms_key",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AC-3 & PCI-DSS 7.2",
        control_ids=["NIST_AC_3", "PCI_DSS_7_2"],
        requirement_id="REQ_KEY_MANAGEMENT",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="policy",
        attribute_value="""  # RegRadar: Restrict KMS key policy to specific role principals""",
        validation_rules=["disallow_wildcard_principal"],
    ),

    # 21. AWS CloudTrail Multi-Region
    "CKV_AWS_67": RemediationRule(
        check_id="CKV_AWS_67",
        name="CloudTrail Multi-Region Logging",
        description="Enforce multi-region audit event logging across all active cloud regions.",
        resource_type="aws_cloudtrail",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AU-2 / AU-3 & PCI-DSS 10.1 & HIPAA §164.312(b)",
        control_ids=["NIST_AU_2", "NIST_AU_3", "PCI_DSS_10_1", "HIPAA_164_312_b"],
        requirement_id="REQ_AUDIT_LOGGING",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="is_multi_region_trail",
        attribute_value="  is_multi_region_trail = true",
        validation_rules=["is_multi_region_trail_true"],
    ),

    # 22. AWS CloudTrail Log File Validation
    "CKV_AWS_35": RemediationRule(
        check_id="CKV_AWS_35",
        name="CloudTrail Log File Validation",
        description="Enable digest log file validation to ensure audit logs cannot be modified undetected.",
        resource_type="aws_cloudtrail",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AU-9 & PCI-DSS 10.5",
        control_ids=["NIST_AU_9", "PCI_DSS_10_5"],
        requirement_id="REQ_SYSTEM_INTEGRITY",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="enable_log_file_validation",
        attribute_value="  enable_log_file_validation = true",
        validation_rules=["enable_log_file_validation_true"],
    ),

    # 23. AWS CloudTrail KMS Encryption
    "CKV_AWS_36": RemediationRule(
        check_id="CKV_AWS_36",
        name="CloudTrail KMS Encryption",
        description="Enforce KMS CMK encryption for all CloudTrail trail log delivery.",
        resource_type="aws_cloudtrail",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 3.4 & NIST SP 800-53 SC-13 & HIPAA §164.312(a)(2)(iv)",
        control_ids=["PCI_DSS_3_4", "NIST_SC_13", "HIPAA_164_312_a_2_iv"],
        requirement_id="REQ_ENCRYPTION_AT_REST",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="kms_key_id",
        attribute_value='  kms_key_id = "aws_kms_key.cloudtrail_key.arn"',
        validation_rules=["kms_key_id_defined"],
    ),

    # 24. AWS Security Group Disallow Public SSH
    "CKV_AWS_24": RemediationRule(
        check_id="CKV_AWS_24",
        name="Security Group Restrict SSH Port 22",
        description="Prohibit unrestricted inbound SSH traffic (port 22) from the public Internet 0.0.0.0/0.",
        resource_type="aws_security_group",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.2 / 1.3 & NIST SP 800-53 AC-4 & HIPAA §164.312(e)(1)",
        control_ids=["PCI_DSS_1_2", "PCI_DSS_1_3", "NIST_AC_4", "HIPAA_164_312_e_1"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="cidr_blocks",
        attribute_value='    cidr_blocks = ["10.0.0.0/8"]',
        validation_rules=["prohibit_quad_zero_cidr"],
    ),

    # 25. AWS Security Group Disallow Public RDP
    "CKV_AWS_25": RemediationRule(
        check_id="CKV_AWS_25",
        name="Security Group Restrict RDP Port 3389",
        description="Prohibit unrestricted inbound RDP traffic (port 3389) from the public Internet 0.0.0.0/0.",
        resource_type="aws_security_group",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.2 / 1.3 & NIST SP 800-53 AC-4",
        control_ids=["PCI_DSS_1_2", "PCI_DSS_1_3", "NIST_AC_4"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="cidr_blocks",
        attribute_value='    cidr_blocks = ["10.0.0.0/8"]',
        validation_rules=["prohibit_quad_zero_cidr"],
    ),

    # 26. AWS VPC Flow Logs
    "CKV_AWS_130": RemediationRule(
        check_id="CKV_AWS_130",
        name="VPC Flow Logs Enabled",
        description="Enforce VPC Flow Logs to record IP traffic entering and exiting virtual network interfaces.",
        resource_type="aws_vpc",
        framework="NIST SP 800-53",
        statute_reference="NIST SP 800-53 AU-2 & PCI-DSS 10.3 & HIPAA §164.312(b)",
        control_ids=["NIST_AU_2", "PCI_DSS_10_3", "HIPAA_164_312_b"],
        requirement_id="REQ_AUDIT_LOGGING",
        strategy=RemediationStrategy.ADDITIVE_ATTACHMENT,
        additive_resource_template="""
resource "aws_flow_log" "{name}_flow_log" {{
  iam_role_arn    = "aws_iam_role.flow_logs.arn"
  log_destination = "aws_cloudwatch_log_group.flow_logs.arn"
  traffic_type    = "ALL"
  vpc_id          = {resource_id}.id
}}
""",
        validation_rules=["traffic_type_all"],
    ),

    # 27. Azure Storage Account Secure Transfer HTTPS
    "CKV_AZURE_3": RemediationRule(
        check_id="CKV_AZURE_3",
        name="Azure Storage Secure Transfer",
        description="Ensure Azure storage accounts enforce HTTPS secure transfer for all incoming requests.",
        resource_type="azurerm_storage_account",
        framework="HIPAA",
        statute_reference="HIPAA §164.312(e)(1) & PCI-DSS 4.1 & GDPR Art. 32 & NIST SC-8",
        control_ids=["HIPAA_164_312_e_1", "PCI_DSS_4_1", "GDPR_Art_32_1_a", "NIST_SC_8"],
        requirement_id="REQ_ENCRYPTION_IN_TRANSIT",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="enable_https_traffic_only",
        attribute_value="  enable_https_traffic_only = true",
        validation_rules=["enable_https_traffic_only_true"],
    ),

    # 28. Azure Storage Account Disable Public Blob Access
    "CKV_AZURE_33": RemediationRule(
        check_id="CKV_AZURE_33",
        name="Azure Storage Disable Public Blob Access",
        description="Prohibit anonymous public read access to blobs and containers in Azure storage accounts.",
        resource_type="azurerm_storage_account",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.3 & NIST SP 800-53 AC-3 & GDPR Art. 32",
        control_ids=["PCI_DSS_1_3", "NIST_AC_3", "GDPR_Art_32_1_b"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="allow_nested_items_to_be_public",
        attribute_value="  allow_nested_items_to_be_public = false",
        validation_rules=["allow_nested_items_to_be_public_false"],
    ),

    # 29. Azure Storage Account Minimum TLS Version
    "CKV_AZURE_44": RemediationRule(
        check_id="CKV_AZURE_44",
        name="Azure Storage Minimum TLS Version",
        description="Enforce modern TLS 1.2 minimum encryption protocol version for Azure storage accounts.",
        resource_type="azurerm_storage_account",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 4.1 & NIST SP 800-53 SC-8",
        control_ids=["PCI_DSS_4_1", "NIST_SC_8"],
        requirement_id="REQ_ENCRYPTION_IN_TRANSIT",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="min_tls_version",
        attribute_value='  min_tls_version = "TLS1_2"',
        validation_rules=["min_tls_version_1_2"],
    ),

    # 30. Azure NSG Deny Unrestricted Public SSH
    "CKV_AZURE_9": RemediationRule(
        check_id="CKV_AZURE_9",
        name="Azure NSG Restrict Public SSH Port 22",
        description="Ensure network security groups block inbound SSH 22 traffic from any Internet IP address (*).",
        resource_type="azurerm_network_security_group",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.2 / 1.3 & NIST SP 800-53 AC-4",
        control_ids=["PCI_DSS_1_2", "PCI_DSS_1_3", "NIST_AC_4"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="source_address_prefix",
        attribute_value='    source_address_prefix = "VirtualNetwork"',
        validation_rules=["source_address_prefix_not_star"],
    ),

    # 31. Azure NSG Deny Unrestricted Public RDP
    "CKV_AZURE_10": RemediationRule(
        check_id="CKV_AZURE_10",
        name="Azure NSG Restrict Public RDP Port 3389",
        description="Ensure network security groups block inbound RDP 3389 traffic from any Internet IP address (*).",
        resource_type="azurerm_network_security_group",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.2 / 1.3 & NIST SP 800-53 AC-4",
        control_ids=["PCI_DSS_1_2", "PCI_DSS_1_3", "NIST_AC_4"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="source_address_prefix",
        attribute_value='    source_address_prefix = "VirtualNetwork"',
        validation_rules=["source_address_prefix_not_star"],
    ),

    # 32. GCP Firewall Deny Open Inbound SSH Port 22
    "CKV_GCP_2": RemediationRule(
        check_id="CKV_GCP_2",
        name="GCP Firewall Restrict Public SSH Port 22",
        description="Ensure Google Cloud firewall rules do not allow unrestricted public ingress to SSH port 22.",
        resource_type="google_compute_firewall",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.2 / 1.3 & NIST SP 800-53 AC-4",
        control_ids=["PCI_DSS_1_2", "PCI_DSS_1_3", "NIST_AC_4"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="source_ranges",
        attribute_value='  source_ranges = ["10.0.0.0/8"]',
        validation_rules=["source_ranges_not_0000"],
    ),

    # 33. GCP Storage Bucket Uniform Bucket-Level Access
    "CKV_GCP_29": RemediationRule(
        check_id="CKV_GCP_29",
        name="GCP Storage Bucket Uniform Bucket-Level Access",
        description="Ensure Google Cloud Storage buckets enforce uniform bucket-level access.",
        resource_type="google_storage_bucket",
        framework="PCI-DSS",
        statute_reference="PCI-DSS 1.3 & NIST SP 800-53 AC-3 & GDPR Art. 32",
        control_ids=["PCI_DSS_1_3", "NIST_AC_3", "GDPR_Art_32_1_b"],
        requirement_id="REQ_ZERO_PUBLIC_INGRESS",
        strategy=RemediationStrategy.IN_PLACE_ATTRIBUTE,
        target_attribute="uniform_bucket_level_access",
        attribute_value="  uniform_bucket_level_access = true",
        validation_rules=["uniform_bucket_level_access_true"],
    ),
}


def find_rules_directory(custom_path: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Finds the rules directory containing externalized regulatory specifications."""
    if custom_path:
        p = Path(custom_path).resolve()
        if p.is_dir():
            return p

    env_path = os.environ.get("REGRADAR_RULES_PATH")
    if env_path:
        p = Path(env_path).resolve()
        if p.is_dir():
            return p

    # Check workspace root
    from regradar.config import resolve_workspace_root
    ws_root = resolve_workspace_root()
    candidate = ws_root / "rules"
    if candidate.is_dir() and (candidate / "remediation_rules.json").is_file():
        return candidate

    pkg_root = Path(__file__).parent.parent.parent.resolve()
    candidate = pkg_root / "rules"
    if candidate.is_dir() and (candidate / "remediation_rules.json").is_file():
        return candidate

    return None


def load_catalog_from_directory(rules_dir: Path) -> Tuple[
    Dict[str, StandardNode],
    Dict[str, ControlNode],
    Dict[str, RequirementNode],
    Dict[str, CloudResourceNode],
    Dict[str, RemediationRule],
]:
    """Loads ontological catalog elements from external JSON rule files."""
    stds_map = dict(STANDARDS)
    ctrls_map = dict(CONTROLS)
    reqs_map = dict(REQUIREMENTS)
    res_map = dict(CLOUD_RESOURCES)
    rules_map = dict(RULES)

    stds_file = rules_dir / "standards.json"
    if stds_file.is_file():
        items = json.loads(stds_file.read_text(encoding="utf-8"))
        for item in items:
            node = StandardNode.model_validate(item)
            stds_map[node.id] = node

    ctrls_file = rules_dir / "controls.json"
    if ctrls_file.is_file():
        items = json.loads(ctrls_file.read_text(encoding="utf-8"))
        for item in items:
            node = ControlNode.model_validate(item)
            ctrls_map[node.id] = node

    reqs_file = rules_dir / "requirements.json"
    if reqs_file.is_file():
        items = json.loads(reqs_file.read_text(encoding="utf-8"))
        for item in items:
            node = RequirementNode.model_validate(item)
            reqs_map[node.id] = node

    res_file = rules_dir / "cloud_resources.json"
    if res_file.is_file():
        items = json.loads(res_file.read_text(encoding="utf-8"))
        for item in items:
            node = CloudResourceNode.model_validate(item)
            res_map[node.id] = node

    rules_file = rules_dir / "remediation_rules.json"
    if rules_file.is_file():
        items = json.loads(rules_file.read_text(encoding="utf-8"))
        for item in items:
            node = RemediationRule.model_validate(item)
            rules_map[node.check_id] = node

    # Check for custom rules in a 'custom' subdirectory if present
    custom_dir = rules_dir / "custom"
    if custom_dir.is_dir():
        for custom_file in custom_dir.glob("*.json"):
            try:
                items = json.loads(custom_file.read_text(encoding="utf-8"))
                if isinstance(items, dict):
                    items = [items]
                for item in items:
                    node = RemediationRule.model_validate(item)
                    rules_map[node.check_id] = node
            except Exception:
                pass

    return stds_map, ctrls_map, reqs_map, res_map, rules_map


def get_default_catalog(rules_dir: Optional[Union[str, Path]] = None) -> Tuple[
    Dict[str, StandardNode],
    Dict[str, ControlNode],
    Dict[str, RequirementNode],
    Dict[str, CloudResourceNode],
    Dict[str, RemediationRule],
]:
    """Returns catalog elements, loaded dynamically from rules/ directory with in-code fallback."""
    found_dir = find_rules_directory(rules_dir)
    if found_dir:
        try:
            return load_catalog_from_directory(found_dir)
        except Exception:
            pass

    return (
        dict(STANDARDS),
        dict(CONTROLS),
        dict(REQUIREMENTS),
        dict(CLOUD_RESOURCES),
        dict(RULES),
    )
