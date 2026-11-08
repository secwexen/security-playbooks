---
id: "ddos-response"
name: "DDoS Response"
category: "response"
status: "active"
version: "1.0.1"
author: "Secwexen"
created_at: "2026-11-08T11:49:00Z"
updated_at: "2026-11-08T11:49:00Z"
description: "Distributed Denial of Service (DDoS) attacks occur when multiple systems generate excessive traffic against network infrastructure or application services, causing resource exhaustion, service degradation, or unavailability."
objective: "Identify, investigate, contain, and mitigate DDoS attacks, determine affected infrastructure and attack vectors, and restore normal service availability."
severity: "critical"
mitre_attack:
  - "T1498.001"
  - "T1498.002"
  - "T1499.002"
  - "T1499.003"
triggers:
  - "Unusual inbound network traffic or bandwidth consumption"
  - "Sudden increases in packets per second or connection requests"
  - "Unexpected service degradation or unavailability"
  - "Abnormally high HTTP or HTTPS request rates"
  - "Network infrastructure or application resource exhaustion"
  - "CDN, WAF, ISP, or DDoS protection alerts"
  - "Monitoring systems detect abnormal traffic patterns"
prerequisites:
  - "Access to network traffic and bandwidth telemetry"
  - "Access to firewall, router, and load balancer logs"
  - "Access to CDN, WAF, and DDoS protection platforms"
  - "Access to application and infrastructure monitoring"
  - "Access to DNS and network-flow telemetry"
  - "Authorized access to network filtering and mitigation capabilities"
  - "Communication channels with ISP and upstream providers"
tags:
  - "ddos"
  - "denial-of-service"
  - "network-security"
  - "availability"
  - "traffic-anomaly"
  - "network-flood"
  - "incident-response"
  - "mitre-attack"
references:
  - "https://attack.mitre.org/techniques/T1498/001/"
  - "https://attack.mitre.org/techniques/T1498/002/"
  - "https://attack.mitre.org/techniques/T1499/002/"
  - "https://attack.mitre.org/techniques/T1499/003/"
steps:
  - id: "identify-alert"
    order: 1
    name: "Identify DDoS Alert"
    action: "investigate"
    description: "Identify the detection source, affected services, target IP addresses, traffic characteristics, detection timestamp, and initial alert context."
    expected_result: "The suspected DDoS activity and affected resources are identified."
  - id: "validate-traffic"
    order: 2
    name: "Validate Traffic Activity"
    action: "analyze"
    description: "Determine whether the observed traffic anomaly is associated with malicious activity, legitimate traffic spikes, or infrastructure failures."
    expected_result: "The legitimacy of the observed traffic activity is assessed."
  - id: "analyze-attack-vector"
    order: 3
    name: "Analyze Attack Vector"
    action: "analyze"
    description: "Examine traffic patterns, protocols, connection behavior, and application requests to identify volumetric, protocol-based, or application-layer attacks."
    expected_result: "The suspected DDoS attack vector and targeted infrastructure layer are identified."
  - id: "determine-scope"
    order: 4
    name: "Determine Attack Scope"
    action: "hunt"
    description: "Identify affected IP addresses, services, network segments, applications, and related infrastructure to establish the attack scope and operational impact."
    expected_result: "The affected infrastructure and potential business impact are determined."
  - id: "mitigate-attack"
    order: 5
    name: "Mitigate DDoS Attack"
    action: "contain"
    description: "Apply approved traffic filtering, rate limiting, traffic scrubbing, CDN, WAF, and upstream mitigation controls in coordination with relevant providers."
    expected_result: "Malicious traffic is mitigated and affected services are protected."
  - id: "restore-services"
    order: 6
    name: "Restore Services"
    action: "respond"
    description: "Restore normal traffic handling, address affected infrastructure resources, and return impacted applications and services to normal operational conditions."
    expected_result: "Affected services are restored to an operational state."
  - id: "verify-service-recovery"
    order: 7
    name: "Verify Service Recovery"
    action: "validate"
    description: "Verify service availability, network performance, infrastructure health, and mitigation effectiveness, and monitor for recurring attack activity."
    expected_result: "Service recovery and mitigation effectiveness are verified."
  - id: "determine-outcome"
    order: 8
    name: "Determine Response Outcome"
    action: "document"
    description: "Classify the incident and document attack characteristics, affected infrastructure, evidence, mitigation actions, service impact, and remaining risks."
    expected_result: "The DDoS incident receives a documented response outcome."
validation:
  validated: false
  required: true
  last_validated: null
  scenario: "ddos-response"
---

# DDoS Response

## Purpose

This playbook provides a structured response workflow for suspected or confirmed Distributed Denial of Service (DDoS) attacks affecting organizational networks, infrastructure, and applications.

DDoS attacks attempt to disrupt service availability by overwhelming network bandwidth, exhausting connection resources, or consuming application and infrastructure capacity.

Attacks may involve volumetric flooding, protocol exhaustion, reflection and amplification, or application-layer request flooding.

The objective is to identify the attack, determine its scope and impact, mitigate malicious traffic, and restore affected services.

## MITRE ATT&CK

| Technique | Name                         | Relevance                                       |
| --------- | ---------------------------- | ----------------------------------------------- |
| T1498.001 | Direct Network Flood         | Excessive traffic directed at network resources |
| T1498.002 | Reflection Amplification     | Amplified traffic directed toward a target      |
| T1499.002 | Service Exhaustion Flood     | Service resource exhaustion                     |
| T1499.003 | Application Exhaustion Flood | Application resource exhaustion                 |

## Trigger Conditions

Start this playbook when one or more of the following conditions are observed:

- Unusual inbound traffic or bandwidth consumption.
- Sudden increases in packets per second or connection rates.
- Unexpected service degradation or unavailability.
- Abnormally high HTTP or HTTPS request volumes.
- Firewall, router, or load balancer resource exhaustion.
- CDN, WAF, or ISP reports suspicious traffic.
- Monitoring systems detect abnormal network activity.
- Unusual traffic distribution originating from multiple external networks or geographic regions.
- Repeated connection attempts targeting specific ports, protocols, or application endpoints.

## Scope

The investigation should consider:

- affected IP addresses;
- affected hostnames and services;
- network protocols and ports;
- inbound bandwidth;
- packets per second;
- connections per second;
- HTTP request rates;
- source IP addresses;
- destination addresses;
- traffic distribution;
- CPU and memory utilization;
- firewall and load balancer health;
- application performance;
- network latency and packet loss;
- service availability;
- business and customer impact.

## Investigation Procedure

### Step 1 — Identify DDoS Alert

Determine:

- detection source;
- alert identifier;
- detection timestamp;
- affected service;
- target IP address;
- network protocol;
- traffic volume;
- source distribution;
- reported service impact;
- destination port;
- peak traffic rate;
- source network and ASN.

Preserve the original alert context and relevant network, infrastructure, and application telemetry.

### Step 2 — Validate Traffic Activity

Determine whether the observed traffic is consistent with legitimate business operations.

Review:

- normal traffic baselines;
- inbound bandwidth;
- connection rates;
- application request patterns;
- expected user activity;
- scheduled events;
- CDN and WAF events;
- infrastructure health;
- historical traffic patterns;
- source geographic distribution;
- recent infrastructure or configuration changes.

A sudden increase in traffic should not automatically be classified as a DDoS attack.

Correlate traffic anomalies with service performance and infrastructure telemetry before assigning the incident classification.

### Step 3 — Analyze Attack Vector

Analyze the traffic characteristics to identify the suspected attack category.

**Volumetric Attacks**

- Excessive inbound bandwidth.
- Unusual UDP or ICMP traffic.
- Abnormal packet rates.
- Network bandwidth saturation.
- Unusual packet-size distribution.

**Protocol Attacks**

- Excessive TCP connection attempts.
- Incomplete TCP handshakes.
- Connection table exhaustion.
- Abnormal protocol behavior.
- Unusual TCP flag distribution.

**Application-Layer Attacks**

- Excessive HTTP or HTTPS requests.
- Repeated requests to resource-intensive endpoints.
- Application worker exhaustion.
- Unusual API request rates.
- Abnormal user-agent and request patterns.

Determine which infrastructure components are targeted and whether multiple attack vectors are involved.

### Step 4 — Determine Attack Scope

Search for:

- additional affected IP addresses;
- related services and applications;
- suspicious traffic patterns;
- affected network segments;
- related firewall and WAF alerts;
- CDN and ISP notifications;
- infrastructure resource exhaustion;
- affected geographic regions;
- related cloud infrastructure;
- previous similar traffic anomalies.

Determine:

- number of affected services;
- peak traffic volume;
- peak connection rates;
- affected infrastructure;
- attack duration;
- service availability impact;
- potential business disruption;
- whether the attack is ongoing.

### Step 5 — Mitigate DDoS Attack

Apply appropriate mitigation controls based on the identified attack vector.

Consider:

- activating ISP or upstream DDoS protection;
- enabling CDN-based traffic protection;
- applying WAF rules and rate limiting;
- configuring network traffic filtering;
- restricting unnecessary exposed ports and protocols;
- activating traffic scrubbing where available;
- protecting origin infrastructure;
- coordinating mitigation with hosting and cloud providers;
- enabling SYN protection where supported;
- applying bot-management challenges;
- optimizing caching for frequently requested content.

Ensure mitigation controls do not unnecessarily block legitimate traffic.

For attacks exceeding available network bandwidth, prioritize upstream mitigation rather than relying exclusively on local firewall filtering.

### Step 6 — Restore Services

Review affected infrastructure and restore normal traffic handling.

Consider:

- restoring network connectivity;
- addressing exhausted infrastructure resources;
- restoring application availability;
- recovering affected backend services;
- reviewing temporary firewall and WAF changes;
- restoring normal traffic-management policies;
- checking database and backend dependencies;
- reviewing DNS resolution;
- removing unnecessary temporary resource restrictions.

Coordinate service recovery with network, infrastructure, and application teams.

### Step 7 — Verify Service Recovery

Verify:

- service availability;
- network bandwidth;
- packet and connection rates;
- application response times;
- infrastructure resource utilization;
- HTTP error rates;
- firewall and load balancer health;
- CDN and WAF protection status;
- DNS resolution;
- application functionality;
- legitimate traffic accessibility.

Confirm that legitimate traffic can access affected services and mitigation controls remain effective.

Continue monitoring for recurring attacks or secondary attack vectors.

### Step 8 — Determine Response Outcome

Classify the incident as:

- **Benign**
- **Suspicious**
- **Malicious**
- **Inconclusive**

Document the evidence supporting the classification and record affected services, attack characteristics, traffic statistics, mitigation actions, service impact, recovery status, and remaining risks.

## Evidence to Collect

| Evidence       | Description                                                     |
| -------------- | --------------------------------------------------------------- |
| Alert          | Detection source, ID, severity, timestamp                       |
| Target         | Affected IP addresses, hostnames, and services                  |
| Network        | Traffic volume, protocols, and packet statistics                |
| Bandwidth      | Inbound consumption and saturation                              |
| TCP            | Connection attempts and TCP state information                   |
| DNS            | Query volume and resolver availability                          |
| HTTP/HTTPS     | Request rates, endpoints, and response codes                    |
| Firewall       | Connection attempts, filtering events, and resource utilization |
| Network Flow   | Source and destination addresses, protocol, and traffic volume  |
| CDN/WAF        | Attack alerts and mitigation events                             |
| Infrastructure | CPU, memory, and connection utilization                         |
| Application    | Response times, errors, and resource consumption                |
| Availability   | Uptime, latency, and packet loss                                |
| Provider       | ISP and DDoS mitigation reports                                 |
| Timeline       | Detection, mitigation, and recovery timestamps                  |

## Decision Criteria

### Benign

Classify the activity as **benign** when:

- traffic is associated with legitimate business operations;
- activity is consistent with expected traffic baselines;
- no malicious traffic patterns are identified;
- service degradation is unrelated to malicious activity;
- traffic originates from expected or authorized sources;
- increased traffic corresponds to scheduled events or business demand;
- network and application resources remain within expected operating limits.

Document the operational justification before closing the incident.

### Suspicious

Classify the activity as **suspicious** when:

- unusual traffic patterns are observed;
- network or application resources show abnormal consumption;
- multiple external sources generate unexpected traffic;
- service degradation is observed;
- malicious activity cannot yet be confirmed;
- traffic characteristics deviate significantly from historical baselines;
- repeated requests target specific services or application endpoints;
- available telemetry indicates potential resource exhaustion.

Continue investigation and maintain appropriate mitigation controls.

### Malicious

Classify the activity as **malicious** when sufficient evidence indicates:

- coordinated traffic overwhelms organizational infrastructure;
- network bandwidth is exhausted by malicious traffic;
- distributed traffic causes service degradation or unavailability;
- reflection or amplification activity targets organizational resources;
- malicious requests exhaust application resources;
- connection-management resources are intentionally exhausted;
- traffic patterns demonstrate coordinated attack activity;
- multiple attack vectors target the same infrastructure;
- DDoS mitigation providers confirm malicious traffic activity.

Escalate to the appropriate incident-response workflow.

### Inconclusive

Use **inconclusive** when available evidence is insufficient to establish whether the observed traffic represents a malicious DDoS attack.

Document:

- evidence collected;
- evidence unavailable;
- telemetry limitations;
- affected services;
- observed traffic characteristics;
- mitigation status;
- additional investigation requirements;
- source attribution limitations;
- unverified service-impact indicators;
- unresolved attack classification.

## Escalation

Escalate the incident when:

- DDoS activity is confirmed;
- critical services become unavailable;
- network bandwidth is saturated;
- multiple services or IP addresses are affected;
- infrastructure resources are exhausted;
- attacks continue despite mitigation;
- ISP or upstream provider intervention is required;
- customer-facing operations are disrupted;
- business continuity procedures may be required;
- Security monitoring or critical infrastructure becomes unavailable during the attack.

## Response Guidance

For confirmed DDoS activity:

1. Preserve network, firewall, router, load balancer, CDN, WAF, and application telemetry.
2. Identify affected IP addresses, hostnames, applications, and infrastructure.
3. Classify the attack vector and determine its scope.
4. Assess service availability and operational impact.
5. Coordinate with ISP, CDN, and DDoS mitigation providers.
6. Apply appropriate upstream and application-layer mitigation.
7. Monitor traffic characteristics and infrastructure health.
8. Restore affected services after attack activity is controlled.
9. Verify service availability and mitigation effectiveness.
10. Document the incident timeline, evidence, response actions, and recovery status.
11. Check for secondary attack vectors and recurring malicious traffic.
12. Preserve mitigation changes, provider actions, and incident communication records.
13. Remove temporary mitigation restrictions after confirming stable service recovery.

Do not rely exclusively on local firewall filtering when upstream network capacity is saturated.

Avoid indiscriminate traffic blocking that could disrupt legitimate users.

## Related Detection Rules

## Related Playbooks

- `playbooks/impact/service-stop.md`
- `playbooks/response/cloud-incident-response.md`
- `playbooks/response/vulnerability-exploitation-response.md`
- `playbooks/discovery/network-discovery.md`

## Validation

The playbook should be validated against controlled network traffic datasets, authorized load-testing scenarios, firewall logs, network telemetry, application monitoring, and DDoS mitigation reports.

Validation should confirm that:

- suspicious traffic patterns can be identified;
- legitimate traffic spikes can be distinguished from malicious activity;
- attack vectors and affected infrastructure can be identified;
- attack scope and service impact can be determined;
- mitigation controls can be applied;
- service recovery can be verified;
- response actions are documented and reproducible;
- upstream DDoS mitigation procedures can be initiated and evaluated;
- legitimate service accessibility can be maintained during mitigation.

## Safety

This playbook is intended for defensive security operations, incident response, controlled laboratory environments, and authorized security validation.

Network filtering, traffic mitigation, firewall modifications, and DDoS testing must only be performed by authorized personnel against explicitly authorized infrastructure.

Preserve relevant forensic evidence without delaying critical mitigation and service recovery. Coordinate response activities with network providers, infrastructure teams, and service owners to minimize operational impact.
