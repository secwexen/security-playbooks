# Quick Start

This guide will help you quickly set up and start using the **Security Playbooks** for educational and lab purposes.

## 1. Prerequisites

Before starting, make sure you have:

- **Python 3.11+** installed  
- Git installed (`git --version`)  
- A safe **lab environment** (virtual machines, containers, or isolated sandbox)  
- Optional: Bash, PowerShell, or Rust toolchains for certain scripts

## 2. Clone the Repository

```bash
# Clone repository
git clone https://github.com/secwexen/security-playbooks.git
cd security-playbooks

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r dev-requirements.txt
```

## 3. Learning Workflow

1. Start by reading **[architecture.md](https://github.com/secwexen/security-playbook/blob/main/docs/architecture.md)** to understand the repo layout.
2. Explore **[detection-rules/](detection-rules/)** to see how threats are detected.

> [!NOTE]
> - Do **not** run scripts on live systems without permission.  
> - Follow ethical and legal guidelines during all testing and lab exercises.
