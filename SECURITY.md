# Security Policy

Security Playbooks values responsible disclosure and safe, ethical security research.
This document outlines the security policy for reporting vulnerabilities, response expectations, and support commitments.

## Reporting Security Issues

If you discover a security vulnerability or issue in this repository, please follow these guidelines:

### Do Not Exploit

Do not attempt to exploit any vulnerability or run scripts against systems you do not own or have explicit permission to test.

### Responsible Disclosure

Report any issues directly to the repository owner.

- **Preferred method**: Open a [private GitHub Security Advisory](https://github.com/secwexen/security-playbooks/security/advisories/new)
- **Include**: Clear description, steps to reproduce, and any relevant files or screenshots

> [!IMPORTANT]
> Do **not disclose security issues publicly** until a fix or mitigation has been released.

### Handling Vulnerabilities

- Security reports will be reviewed as soon as possible (within 24 business hours).  
- Initial acknowledgment will be provided to the reporter.
- Fixes or updates will be applied and documented in the repository.
- The reporter will be credited in the security advisory (unless anonymity is requested).

## Response Expectations

- **Initial response**: We aim to respond within 24 business hours  
- **Fix or mitigation**: Within 7-14 days for critical issues, longer for non-critical  
- **Security issues** will be tracked via a ticket system or CVE where applicable  
- **Coordinated disclosure** will be handled in collaboration with the reporter

## Bug Bounty Program

Currently, **Security Playbooks does not operate a formal bug bounty program**. However, security researchers who responsibly disclose vulnerabilities will receive:

- Recognition in project documentation
- Opportunity to contribute fixes

We encourage security research and appreciate responsible disclosure practices.

## Patch & Release Policy

### Patch Release Schedule

- **Critical Security Patches**: Released immediately upon verification
- **High Priority Patches**: Released within 7 days
- **Standard Updates**: Released as part of regular release cycles (typically monthly)

### Version Support

| Version | Status | Security Support |
|---------|--------|------------------|
| Latest Stable | Active | Full support |
| Previous Minor | Maintenance | Critical patches only |
| Older Versions | End of Life | No support |

**Support Timeline**:

- Latest stable version receives security updates indefinitely
- Previous minor version (N-1) receives critical patches for 6 months
- Versions older than N-1 are not supported

Users are strongly encouraged to keep their installations up to date.

### Dependency Management

- Dependencies are regularly reviewed and updated
- Security vulnerabilities in dependencies are addressed with priority
- Automated scanning is performed to detect vulnerable dependencies

## CVE Process

Where applicable, security vulnerabilities may be assigned a **CVE (Common Vulnerabilities and Exposures)** identifier.

We will coordinate with the reporter to request and publish CVEs for confirmed issues, ensuring transparency and industry-standard tracking.

## Supported Versions

Security updates are provided based on the following policy:

- **Latest Stable Release**: Full security support
- **Previous Minor Release**: Critical security patches only (6 months)
- **Older Versions**: End of Life — no security updates provided

Users are encouraged to upgrade to the latest stable release to receive all security patches.

## Security Best Practices

- All scripts and labs are intended for **educational and lab use only**.  
- Use **isolated environments** (VMs, containers, sandboxes) to avoid affecting production systems.  
- Follow **ethical guidelines** and local laws when experimenting with scripts or scenarios.
- Keep your Python environment and dependencies updated
- Review code before execution, especially in security contexts
- Use this repository only in authorized, controlled environments

## Acknowledgments

Thank you to all security researchers who help improve the security of this project through responsible disclosure.
