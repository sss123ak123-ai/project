# AI Web Assistant

AI-assisted web vulnerability analysis framework focused on ethical, authorized testing scopes. The assistant behaves like a security analyst: it analyzes HTTP responses, judges likelihood, reduces false positives, and emits structured JSON decisions without generating exploits.

## Features
- Modular detectors for XSS, error-based SQLi, SSTI execution indicators, open redirects, information disclosure, and security header misconfigurations.
- AI judgement engine producing strict JSON with confidence and rationale.
- Scope enforcement, rate limiting, and early-stop on high-confidence findings for safety.
- Structured reports written to JSON with verbose logging for auditability.
- Safe payloads only; no exploitation, authentication bypass, or privilege escalation.

## Project Structure
```
ai-web-assistant/
├── core/                  # orchestration, AI judge, request handling, logging
├── modules/               # vulnerability-specific detectors
├── payloads/              # reserved for custom payload lists
├── reports/               # generated JSON reports
├── logs/                  # framework logs
├── config.yaml            # configuration and scopes
├── requirements.txt       # Python dependencies
└── main.py                # entrypoint
```

## Usage
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Edit `config.yaml` to include authorized `allowed_domains` and `targets`.
3. Run the orchestrator:
   ```bash
   python ai-web-assistant/main.py -c ai-web-assistant/config.yaml
   ```
   Optionally, specify `--output` to write a consolidated JSON file.

## Example Output
```json
{
  "is_vulnerable": true,
  "vulnerability_type": "XSS",
  "confidence": "high",
  "reason": "Potential XSS due to reflected payload and script-like context.",
  "recommended_next_step": "Manual confirmation with browser-based context and screenshot."
}
```

## Legal & Ethical Disclaimer
- For authorized security testing and bug bounty scopes only.
- Uses safe payloads and stops after the first high-confidence finding.
- Does not attempt exploitation, privilege escalation, or data access beyond detection.
- You are responsible for adhering to relevant laws and program rules.
