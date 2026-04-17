# Run Commands

## New Lab & Scenario Commands

### Sigma Parser Script

```
python sigma_parser.py
```

### Suricata T1059 logs

```
sudo suricata -r examples/powershell_log_example.txt -c /etc/suricata/suricata.yaml
```

### YARA test for T1059

```
yara detection-rules/yara/yara_powershell_payload.yar examples/powershell_log_example.txt
```

### Parser script with scenario logs

```
python labs/lab2_log_analysis/parser.py examples/malware_log_example.txt
python labs/lab2_log_analysis/parser.py examples/powershell_log_example.txt
python labs/lab2_log_analysis/parser.py examples/phishing_log_example.txt
```

## Log File

Used automatically by parser.py:
```
examples/malware_log_example.txt
examples/powershell_log_example.txt
examples/phishing_log_example.txt
```
