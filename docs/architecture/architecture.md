# Architecture

The Security Playbooks is structured to provide a clear, modular, and professional layout for cybersecurity research, lab simulations. The architecture is designed for educational, hands-on use while maintaining real-world workflow relevance.

## Project Structure

```text
security-playbooks
├── ACKNOWLEDGEMENTS.md
├── CHANGELOG.md
├── CITATION.cff
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── DISCLAIMER.md
├── Dockerfile
├── LICENSE
├── MAINTAINERS
├── MANIFEST.yaml
├── Makefile
├── README.md
├── ROADMAP.md
├── SECURITY.md
├── SUPPORT.md
├── assets
│   └── images
│       └── security-playbooks-logo.png
├── automation
│   ├── enrichment
│   │   ├── ioc_enrichment.py
│   │   └── threat_feed_sync.py
│   └── validation
│       └── validate_pipeline.py
├── config
│   ├── detection-pipeline.yml
│   ├── logging.yml
│   ├── sigma.yml
│   ├── suricata.yml
│   └── yara.yml
├── detection-rules
│   ├── README.md
│   ├── examples
│   │   ├── sigma-example.yml
│   │   ├── suricata-example.rules
│   │   └── yara-example.yar
│   ├── mappings
│   │   ├── attack-coverage.json
│   │   ├── attack-navigator-layer.json
│   │   ├── coverage-matrix.md
│   │   ├── coverage-report.json
│   │   ├── mitre-mapping.yaml
│   │   ├── mitre-summary.md
│   │   └── rule-coverage-map.json
│   ├── metadata
│   │   ├── confidence.yaml
│   │   ├── false-positive.yaml
│   │   ├── ownership.yaml
│   │   ├── rule-schema.yaml
│   │   ├── severity.yaml
│   │   └── status.yaml
│   ├── registry.yaml
│   ├── sigma
│   │   ├── lsass-access.yml
│   │   ├── sigma-powershell-exec.yml
│   │   └── suspicious-login.yml
│   ├── suricata
│   │   ├── c2-communication.rules
│   │   ├── network-alert.rules
│   │   └── powershell-alert.rules
│   └── yara
│       ├── malware-sample.yar
│       ├── obfuscated-powershell.yar
│       └── yara-powershell-payload.yar
├── docker-compose.yml
├── docs
│   ├── FAQ.md
│   ├── INDEX.md
│   ├── README.md
│   ├── architecture
│   │   ├── architecture.md
│   │   ├── detection-validation.md
│   │   └── threat-model.md
│   ├── contributing
│   │   └── commit-convention.md
│   ├── detection-engineering
│   │   ├── rule-lifecycle.md
│   │   ├── rule-style-guide.md
│   │   ├── sigma-development.md
│   │   ├── tuning
│   │   │   ├── false-positive-reduction.md
│   │   │   ├── rule-optimization.md
│   │   │   └── tuning-process.md
│   │   └── validation-process.md
│   ├── executive
│   │   └── vision.md
│   ├── getting-started
│   │   ├── getting-started.md
│   │   ├── installation.md
│   │   └── quickstart.md
│   ├── guides
│   │   ├── development.md
│   │   └── usage.md
│   ├── incident-response
│   │   └── project-lifecycle.md
│   ├── legal
│   │   ├── ethics.md
│   │   └── terms-of-service.md
│   ├── operations
│   │   ├── alert-triage.md
│   │   ├── escalation-process.md
│   │   ├── incident-handling.md
│   │   └── soc-workflow.md
│   ├── playbook-guide.md
│   ├── product
│   │   ├── features.md
│   │   ├── overview.md
│   │   └── what-is-security-playbooks.md
│   ├── reference
│   │   └── references.md
│   ├── testing
│   │   └── testing.md
│   └── threat-hunting
│       ├── hunting-process.md
│       ├── hypothesis-driven-hunting.md
│       ├── methodology.md
│       └── query-guidelines.md
├── integrations
│   ├── crowdstrike.md
│   ├── elastic.md
│   ├── microsoft-defender.md
│   ├── sentinel.md
│   ├── sigma-backends.md
│   ├── slack.md
│   └── splunk.md
├── iocs
│   ├── domains.txt
│   ├── feeds
│   │   ├── abuseipdb.json
│   │   ├── alienvault-otx.json
│   │   ├── feeds-metadata.yaml
│   │   └── internal-feed.json
│   ├── file-hashes.txt
│   ├── iocs.json
│   ├── ips.txt
│   ├── metadata
│   │   ├── confidence.yaml
│   │   ├── status.yaml
│   │   └── types.yaml
│   ├── threat_feed.json
│   └── urls.txt
├── labs
│   ├── datasets
│   │   ├── README.md
│   │   ├── linux
│   │   │   └── syslog.json
│   │   ├── network
│   │   │   └── network_logs.json
│   │   └── windows
│   │       ├── auth_logs.json
│   │       ├── pcaps
│   │       │   ├── attack_traffic.pcap
│   │       │   └── sample_traffic.pcap
│   │       └── sysmon.json
│   ├── lab-manifest.yaml
│   ├── logs
│   │   ├── auth_logs.json
│   │   └── network_logs.json
│   ├── samples
│   │   ├── benign
│   │   │   └── clean_activity.json
│   │   └── events
│   │       ├── auth_logs.json
│   │       └── network_flows.json
│   └── scenarios
│       ├── cloud-compromise.json
│       ├── credential-dumping.json
│       ├── credential-theft-chain.json
│       ├── insider-threat.json
│       ├── lateral-movement-chain.json
│       ├── phishing-to-ransomware.json
│       └── ransomware-attack.json
├── playbooks
│   ├── README.md
│   ├── cloud
│   │   ├── application-access-token-abuse.md
│   │   ├── cloud-account-compromise.md
│   │   ├── cloud-account-discovery.md
│   │   ├── cloud-credential-access.md
│   │   ├── cloud-infrastructure-discovery.md
│   │   ├── cloud-secrets-access.md
│   │   ├── cloud-service-dashboard.md
│   │   ├── cloud-service-discovery.md
│   │   └── cloud-storage-object-discovery.md
│   ├── collection
│   │   ├── archive-collected-data.md
│   │   ├── browser-data.md
│   │   ├── clipboard-theft.md
│   │   ├── keylogging.md
│   │   └── screen-capture.md
│   ├── command-and-control
│   │   ├── application-layer-protocol.md
│   │   ├── beaconing.md
│   │   ├── dns-c2.md
│   │   ├── encrypted-channel.md
│   │   ├── fallback-channel.md
│   │   ├── ingress-tool-transfer.md
│   │   ├── proxy-tunneling.md
│   │   └── web-c2.md
│   ├── credential-access
│   │   ├── asrep-roasting.md
│   │   ├── browser-credential-theft.md
│   │   ├── credential-access.md
│   │   ├── credential-dumping.md
│   │   ├── credentials-from-password-stores.md
│   │   ├── dpapi-credential-access.md
│   │   ├── kerberoasting.md
│   │   ├── lsass-dump.md
│   │   ├── ntds-dump.md
│   │   ├── password-manager-credential-theft.md
│   │   ├── password-spraying.md
│   │   ├── sam-dump.md
│   │   └── windows-credential-manager.md
│   ├── defense-evasion
│   │   ├── amsi-bypass.md
│   │   ├── credential-security-tool-disabling.md
│   │   ├── disable-defender.md
│   │   ├── event-log-clearing.md
│   │   ├── lolbins.md
│   │   ├── masquerading.md
│   │   ├── obfuscated-powershell.md
│   │   ├── process-injection.md
│   │   └── timestomp.md
│   ├── discovery
│   │   ├── account-discovery.md
│   │   ├── domain-trust-discovery.md
│   │   ├── file-and-directory-discovery.md
│   │   ├── group-discovery.md
│   │   ├── network-discovery.md
│   │   ├── permission-discovery.md
│   │   ├── process-discovery.md
│   │   ├── security-tool-discovery.md
│   │   ├── service-discovery.md
│   │   ├── software-discovery.md
│   │   └── system-info-discovery.md
│   ├── execution
│   │   ├── command-shell.md
│   │   ├── mshta.md
│   │   ├── powershell.md
│   │   ├── python-execution.md
│   │   ├── scheduled-task-execution.md
│   │   ├── scripting.md
│   │   ├── user-execution.md
│   │   └── wmi-execution.md
│   ├── exfiltration
│   │   ├── cloud-exfiltration.md
│   │   ├── data-exfiltration.md
│   │   └── dns-exfiltration.md
│   ├── impact
│   │   ├── data-destruction.md
│   │   └── ransomware.md
│   ├── initial-access
│   │   ├── application-consent-abuse.md
│   │   ├── drive-by-download.md
│   │   ├── exploit-public-facing-application.md
│   │   ├── malicious-attachment.md
│   │   ├── phishing.md
│   │   └── valid-account-compromise.md
│   ├── lateral-movement
│   │   ├── pass-the-hash.md
│   │   ├── pass-the-ticket.md
│   │   ├── rdp-lateral-movement.md
│   │   ├── smb-lateral-movement.md
│   │   ├── winrm-lateral-movement.md
│   │   └── wmi-lateral-movement.md
│   ├── persistence
│   │   ├── registry-run-keys.md
│   │   ├── scheduled-task-persistence.md
│   │   ├── service-persistence.md
│   │   └── startup-folder.md
│   ├── privilege-escalation
│   │   ├── privileged-service-abuse.md
│   │   ├── scheduled-task-abuse.md
│   │   ├── service-permission-abuse.md
│   │   ├── token-manipulation.md
│   │   ├── uac-bypass.md
│   │   ├── unquoted-service-path.md
│   │   └── weak-service-permissions.md
│   ├── response
│   │   ├── account-compromise-response.md
│   │   ├── credential-compromise-response.md
│   │   ├── data-exfiltration-response.md
│   │   ├── isolate-host-response.md
│   │   ├── lateral-movement-response.md
│   │   ├── malware-response.md
│   │   ├── persistence-removal-response.md
│   │   ├── phishing-response.md
│   │   └── ransomware-response.md
│   └── triage
│       ├── data-exfiltration-triage.md
│       ├── email-compromise-triage.md
│       ├── lateral-movement-triage.md
│       ├── malware-detection-triage.md
│       ├── persistence-triage.md
│       ├── phishing-alert-triage.md
│       ├── suspicious-file-triage.md
│       ├── suspicious-login-triage.md
│       ├── suspicious-powershell-triage.md
│       └── suspicious-process-triage.md
├── pyproject.toml
├── reports
│   ├── attack-simulation-report.json
│   ├── coverage-analysis.json
│   ├── coverage-dashboard.json
│   ├── coverage-report.html
│   ├── coverage-report.json
│   ├── coverage-summary.md
│   ├── detection-gap-report.md
│   ├── execution-trace.json
│   ├── index.json
│   └── validation-summary.json
├── requirements-dev.txt
├── requirements.txt
├── schemas
│   ├── alert_schema.json
│   ├── detection_rule.schema.json
│   ├── enrichment.schema.json
│   ├── hunt_hypothesis.schema.json
│   ├── hunt_report.schema.json
│   ├── incident.schema.json
│   ├── ioc.schema.json
│   ├── log_schema.json
│   └── playbook.schema.json
├── scripts
│   ├── export_attack_matrix.py
│   ├── run_sigma_tests.py
│   ├── run_suricata_tests.py
│   ├── run_yara_tests.py
│   └── validate_all_rules.py
├── templates
│   ├── playbook-template.md
│   ├── sigma-template.yml
│   └── yara-template.yar
├── tests
│   ├── conftest.py
│   ├── integration
│   │   ├── test_detection_pipeline.py
│   │   ├── test_ioc_pipeline.py
│   │   ├── test_playbook_validation.py
│   │   └── test_rule_validation.py
│   ├── mappings
│   │   ├── test_attack_coverage.py
│   │   ├── test_coverage_consistency.py
│   │   └── test_mitre_mapping.py
│   ├── playbooks
│   │   ├── test_playbook_links.py
│   │   ├── test_playbook_metadata.py
│   │   ├── test_playbook_schema_validation.py
│   │   └── test_playbook_structure.py
│   ├── schemas
│   │   ├── test_alert_schema.py
│   │   ├── test_detection_rule_schema.py
│   │   ├── test_enrichment_schema.py
│   │   ├── test_incident_schema.py
│   │   ├── test_ioc_schema.py
│   │   ├── test_log_schema.py
│   │   └── test_playbook_schema.py
│   ├── sigma
│   │   ├── fixtures
│   │   │   ├── expected_results.json
│   │   │   ├── lsass_events.json
│   │   │   ├── powershell_events.json
│   │   │   └── suspicious_login_events.json
│   │   ├── test-cases.yaml
│   │   └── test_sigma_rules.py
│   ├── suricata
│   │   ├── fixtures
│   │   │   ├── c2_http.pcap
│   │   │   ├── dns_tunnel.pcap
│   │   │   ├── expected_alerts.json
│   │   │   └── sample_traffic.pcap
│   │   ├── generate_fixtures.py
│   │   ├── test-pcaps.yaml
│   │   └── test_suricata_rules.py
│   ├── threat-hunting
│   │   ├── test_hunt_reports.py
│   │   ├── test_hypotheses.py
│   │   └── test_queries.py
│   ├── threat-intelligence
│   │   ├── test_feed_metadata.py
│   │   ├── test_ioc_metadata.py
│   │   ├── test_mitre_actor_mapping.py
│   │   └── test_sources.py
│   ├── unit
│   │   ├── test_attack_mapping.py
│   │   ├── test_ioc_enrichment.py
│   │   ├── test_logger.py
│   │   ├── test_pipeline_validation.py
│   │   ├── test_sigma_parser.py
│   │   └── test_threat_feed_sync.py
│   └── yara
│       ├── fixtures
│       │   ├── benign_sample.txt
│       │   ├── expected_matches.json
│       │   └── malicious_sample.txt
│       ├── test-samples.yaml
│       └── test_yara_rules.py
├── threat-hunting
│   ├── README.md
│   ├── hunt-reports
│   │   └── hunt-report-template.md
│   ├── hypotheses
│   │   ├── collection.md
│   │   ├── command-and-control.md
│   │   ├── credential-access.md
│   │   ├── defense-evasion.md
│   │   ├── discovery.md
│   │   ├── execution.md
│   │   ├── exfiltration.md
│   │   ├── impact.md
│   │   ├── initial-access.md
│   │   ├── lateral-movement.md
│   │   ├── persistence.md
│   │   └── privilege-escalation.md
│   ├── methodology.md
│   └── queries
│       ├── elastic
│       │   ├── authentication-hunting.json
│       │   ├── network-hunting.json
│       │   └── process-hunting.json
│       ├── kql
│       │   ├── credential-access.kql
│       │   ├── lateral-movement.kql
│       │   ├── malware-hunting.kql
│       │   ├── persistence.kql
│       │   ├── ransomware-hunting.kql
│       │   └── suspicious-login.kql
│       └── spl
│           ├── privilege-escalation.spl
│           ├── ransomware-behavior.spl
│           └── suspicious-process.spl
├── threat-intelligence
│   ├── README.md
│   ├── actors
│   │   ├── apt-groups.md
│   │   ├── ransomware-groups.md
│   │   └── threat-actor-template.md
│   ├── campaigns
│   │   ├── campaign-template.md
│   │   └── phishing-campaigns.md
│   ├── feeds
│   │   └── feed-management.md
│   ├── indicators
│   │   ├── enrichment.md
│   │   └── ioc-analysis-template.md
│   ├── malware
│   │   ├── infostealers.md
│   │   ├── malware-family-template.md
│   │   └── ransomware.md
│   ├── mappings
│   │   └── mitre-actor-mapping.yaml
│   ├── reports
│   │   ├── intelligence-summary.md
│   │   └── threat-report-template.md
│   ├── sources
│   │   └── sources.yaml
│   ├── tlp.md
│   └── vulnerabilities
│       ├── cve-template.md
│       ├── exploited-vulnerabilities.md
│       └── vulnerability-tracking.md
├── tools
│   ├── __init__.py
│   ├── parsers
│   │   ├── __init__.py
│   │   └── sigma_parser.py
│   ├── reports
│   │   └── coverage_report.py
│   └── utils
│       ├── __init__.py
│       └── logger.py
└── validation
    ├── README.md
    ├── methodology.md
    ├── scenarios
    │   ├── lateral-movement.md
    │   ├── phishing-chain.md
    │   ├── phishing.md
    │   ├── powershell-execution.md
    │   └── ransomware.md
    ├── sigma
    │   ├── expected_results.json
    │   ├── test_cases.yaml
    │   └── validation_report.json
    ├── suricata
    │   ├── expected_alerts.json
    │   └── test_pcaps
    │       ├── c2_http.pcap
    │       ├── dns_tunnel.pcap
    │       └── sample_traffic.pcap
    └── yara
        ├── expected_matches.json
        └── test_samples
            ├── benign_sample.txt
            └── malicious_sample.txt
```
