# Security Policy

## Supported Versions

Security fixes are considered for the latest development version of Tracelet.

Older versions may not receive security updates.

## Reporting a Vulnerability

If you discover a potential security vulnerability in Tracelet, please report it privately rather than opening a public issue.

Use GitHub's private vulnerability reporting feature if it is available for this repository.

If private reporting is unavailable, contact the repository maintainer through a private communication channel before publicly disclosing the vulnerability.

## What to Include

Please provide as much of the following information as possible:

- A description of the vulnerability.
- The affected component or feature.
- Steps to reproduce the issue.
- A minimal proof of concept, if available.
- The potential impact.
- Any suggested mitigation or fix.

Please avoid including sensitive personal information or confidential system data.

## Scope

Security reports may involve:

- Unsafe handling of kernel or userspace event data.
- Memory safety issues in userspace code.
- Incorrect validation of eBPF event payloads.
- Privilege or capability handling.
- Unintended information disclosure.
- Vulnerabilities in build or release workflows.
- Dependency-related security issues.

## Disclosure

Please allow reasonable time for the issue to be investigated and addressed before publicly disclosing technical details.

The maintainer may request additional information to reproduce and verify the issue.

## Security Limitations

Tracelet interacts with Linux kernel tracing facilities and may require elevated privileges or specific capabilities.

Users should understand the permissions and security implications of running tracing tools on their systems.

This policy does not guarantee that every report will result in a security fix or that every affected environment can be supported.
