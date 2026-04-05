# SyslogStudio Test Tools

## syslog_generator.py

A comprehensive syslog message generator for testing SyslogStudio. No dependencies required (Python 3.7+ standard library only).

### Quick Start

```bash
# Start SyslogStudio with UDP enabled on port 514, then:
python tools/syslog_generator.py
```

### Modes

| Mode | Description |
|------|-------------|
| `continuous` | Send at a fixed rate until Ctrl+C (default) |
| `burst` | Send N messages as fast as possible |
| `scenario` | Simulate a realistic server incident timeline |
| `alert-test` | Send specific messages designed to trigger alert rules |
| `stress` | Maximum throughput for 30 seconds |

### Examples

```bash
# 10 messages/second, realistic mix
python tools/syslog_generator.py --rate 10

# Lots of errors and warnings
python tools/syslog_generator.py --rate 5 --profile stressed

# TCP mode
python tools/syslog_generator.py --protocol tcp --port 514

# TLS with CA certificate
python tools/syslog_generator.py --protocol tls --port 6514 --ca-cert ca-cert.pem

# Burst 5000 messages
python tools/syslog_generator.py --mode burst --count 5000

# Incident simulation (7 phases, ~2 minutes)
python tools/syslog_generator.py --mode scenario

# Test alert rules
python tools/syslog_generator.py --mode alert-test

# Stress test (30 seconds max throughput)
python tools/syslog_generator.py --mode stress

# BSD format instead of RFC 5424
python tools/syslog_generator.py --format rfc3164
```

### Severity Profiles

| Profile | Description |
|---------|-------------|
| `quiet` | 70% info, minimal errors |
| `normal` | Realistic production mix (default) |
| `stressed` | 25% warnings + 25% errors |
| `critical` | 30% errors + 20% critical |
