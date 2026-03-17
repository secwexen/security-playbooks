# Quick Start Guide

This guide will help you quickly set up and start using the **Security Playbook** for educational and lab purposes.

## 1. Prerequisites

Before starting, make sure you have:

- **Python 3.11+** installed  
- Git installed (`git --version`)  
- A safe **lab environment** (virtual machines, containers, or isolated sandbox)  
- Optional: Bash, PowerShell, or Rust toolchains for certain scripts


## 2. Clone the Repository

```bash
git clone https://github.com/secwexen/security-playbook.git
cd security-playbook
```

## 3. Install Dependencies

Some PoC scripts may require additional Python packages. You can install them using:

```bash
pip install -r requirements.txt
```

> Note: Create a virtual environment to avoid conflicts with your system Python.

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

## 4. Explore the Repository

- **detection-rules/** – Review Sigma, YARA, and Suricata rules
- **scenarios/** – Start with MITRE ATT&CK attack simulations
- **labs/** – Run PoC scripts in isolated environments
- **examples/** – Check sample outputs and logs
- **docs/** – Read architecture and guides
- **tools/** – Use helper scripts if needed

## 5. Running a Lab Scenario

Example: Running a network scan lab:

```bash
cd labs/lab1_network_scan
python scan.py
```

> Always ensure you are in a **safe lab environment** before executing any scripts.

## 6. Learning Workflow

1. Start by reading **[architecture.md](https://github.com/secwexen/security-playbook/blob/main/docs/architecture.md)** to understand the repo layout.
2. Explore **[detection-rules/](detection-rules/)** to see how threats are detected.
3. Execute **[scenarios/](https://github.com/secwexen/security-playbook/tree/main/scenarios)** and **[labs/](https://github.com/secwexen/security-playbook/tree/main/labs)** to learn attack simulation and response.
4. Reference **[examples/](https://github.com/secwexen/security-playbook/tree/main/examples)** to validate results and outputs.

## 7. Notes

- All scripts are for **educational purposes only**.
- Do **not** run scripts on live systems without permission.
- Follow ethical and legal guidelines during all testing and lab exercises.
