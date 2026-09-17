# Security Policy

## Responsible Disclosure

Please do not report security vulnerabilities through public GitHub Issues, pull requests, Discussions, or comments. Public reports can expose other users before maintainers have time to investigate and respond.

To report a vulnerability privately, email:

`security@openpayload.io`

Include only information that is safe to share with the maintainers and necessary to investigate the report. Do not include credentials, secrets, private keys, customer data, or proprietary source code unless the maintainers explicitly request a secure transfer method.

## What to Include

Please include:

- A clear summary of the suspected vulnerability.
- Affected versions, components, or public releases if known.
- Reproduction steps using sanitized examples.
- The potential impact.
- Any relevant sanitized logs, screenshots, or proof-of-concept details.

Avoid including:

- Credentials, tokens, certificates, passwords, or private keys.
- Customer data or personal information.
- Proprietary source code from private repositories.
- Internal infrastructure details.
- Security-sensitive design information beyond what is needed for the report.

## Expected Response Timeline

Maintainers will make a good-faith effort to follow these timelines:

- Initial acknowledgement: within 3 business days.
- Initial assessment and severity classification: within 10 business days.
- Status updates: at least every 15 business days while the report remains open.
- Coordinated disclosure: after a fix, mitigation, or documented risk decision is available.

Timelines may vary depending on severity, complexity, maintainer availability, and whether additional information is needed.

## Severity Classification

Maintainers use the following general guidance when assessing reports:

- Critical: Vulnerabilities that may allow remote code execution, credential compromise, broad unauthorized access, or severe data exposure.
- High: Vulnerabilities that may allow privilege escalation, unauthorized access to sensitive functionality, significant data exposure, or reliable exploitation with limited prerequisites.
- Medium: Vulnerabilities that require specific conditions, limited privileges, or user interaction, and have moderate confidentiality, integrity, or availability impact.
- Low: Vulnerabilities with limited impact, significant prerequisites, defense-in-depth concerns, or issues that disclose minimal non-sensitive information.

Final severity is determined by maintainers based on exploitability, impact, affected versions, and available mitigations.

## Public Disclosure

This repository is public. All public issues, pull requests, comments, and attachments must be safe for public disclosure. Maintainers may redact, hide, or remove content that appears to include confidential, proprietary, personal, or security-sensitive information.
