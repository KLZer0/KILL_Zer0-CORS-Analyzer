# KILL_Zer0 CORS Analyzer v1.0.0

A Burp Suite Jython extension for analyzing CORS behavior and generating PoC templates for manual verification.

## Features

- Baseline CORS response analysis
- Origin probing
- Trusted `null` origin detection
- Arbitrary origin reflection detection
- Prefix/suffix validation weakness checks
- HTTP/HTTPS subdomain trust checks
- Wildcard CORS informational detection
- Private-network CORS signal detection
- Preflight requirement prediction
- Response-sensitivity heuristics
- PoC generation for relevant CORS behavior

## Requirements

- Burp Suite
- Jython environment compatible with the extension
- A Burp request selected from an appropriate context such as Proxy HTTP history

## Installation

1. Open Burp Suite.
2. Go to **Extensions**.
3. Configure the extension for **Python/Jython**.
4. Select `KILL_Zer0-CORS-Analyzer.py`.
5. Load the extension.
6. Select an HTTP request in Burp and use:

**Analyze CORS Behavior & Generate PoC**

## Usage

The extension asks for an exploit-server URL used by generated PoC templates.

The analysis performs:

1. Baseline request analysis.
2. Origin probes.
3. CORS header correlation.
4. Response-sensitivity heuristics.
5. Scenario classification.
6. PoC template generation where applicable.

## Important: Manual Verification

The extension reports **CORS behavior signals**, not confirmed vulnerabilities.

A reflected origin, `Access-Control-Allow-Credentials: true`, or another CORS behavior does not by itself prove that sensitive information is exposed.

Always manually verify:

- Whether the response is readable cross-origin.
- Whether the response contains sensitive/user-specific information.
- Whether credentials are actually involved.
- Whether the reported behavior is exploitable in the target environment.

The preflight section is a prediction based on the request structure; the extension does not send an actual `OPTIONS` preflight request.

The response-sensitivity check is a keyword-based heuristic and is not exhaustive.

## Version

**v1.0.0**

This is the first public version of the project. Future releases may improve detection accuracy, coverage, reporting, and usability.

## Responsible Use

Use this extension only against systems you own or have explicit authorization to test.

## Author

Omar Khalid
