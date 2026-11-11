# RegRadar Regulatory Rules Catalog

This directory contains externalized statutory compliance definitions, controls, and zero-destruction remediation rules for RegRadar.

## Catalog Files
- `standards.json`: Statutory regulatory standards (HIPAA, GDPR, NIST SP 800-53, PCI-DSS).
- `controls.json`: Specific regulatory statutes and sections (e.g., HIPAA §164.312(a)(2)(iv), GDPR Art. 32(1)(a)).
- `requirements.json`: Abstract security and privacy requirements (Encryption at Rest, Public Access Block, etc.).
- `cloud_resources.json`: Supported cloud infrastructure resource definitions (AWS, Azure, GCP).
- `remediation_rules.json`: Checkov check IDs mapped to statutory citations, HCL templates, and remediation strategies.

## Adding Custom Policies
To inject custom organizational rules without modifying Python code, place a JSON file in `rules/custom/`:

```json
[
  {
    "check_id": "CKV_CUSTOM_01",
    "name": "Custom Organization Security Tag",
    "description": "Ensure resources have required SecurityZone tag",
    "resource_type": "aws_s3_bucket",
    "framework": "Internal Policy",
    "statute_reference": "Corp Sec 4.1",
    "control_ids": [],
    "requirement_id": null,
    "strategy": "IN_PLACE_ATTRIBUTE",
    "target_attribute": "tags.SecurityZone",
    "attribute_value": "  tags = { SecurityZone = \"restricted\" }",
    "validation_rules": []
  }
]
```

RegRadar automatically loads and merges any rules found in `rules/custom/*.json` during startup.
