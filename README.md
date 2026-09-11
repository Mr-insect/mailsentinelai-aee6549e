# MailSentinel AI

Build a complete, polished, hackathon-ready cybersecurity web application called:

"MailSentinel AI"

Subtitle:
"AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence"

IMPORTANT CONTEXT:

This is a university internal hackathon project.

The main goal is to create a highly impressive WORKING DEMO that judges can interact with.

The application should allow a user to upload an email file (.EML), analyze the email, detect suspicious behavior, perform email authentication analysis, extract indicators of compromise, provide IP/domain geolocation intelligence, and present a forensic investigation report.

I am a beginner and I do not have deep React/API/backend knowledge.

Therefore:

1. The application MUST work immediately after running.
2. Do NOT make the application dependent on external APIs.
3. Build a realistic DEMO/MOCK intelligence layer first.
4. Structure the code so real APIs can easily be connected later.
5. Never expose API keys in frontend code.
6. Never make fake API calls that cause the application to break.
7. If a real API is unavailable, gracefully fall back to demo data.
8. Every major button must actually do something.
9. Do not create non-functional placeholder buttons.
10. The application should look like a professional cybersecurity SOC platform rather than a basic college project.

==================================================
TECHNOLOGY
==================================================

Frontend:

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- Lucide icons
- Recharts
- Leaflet/OpenStreetMap for geolocation visualization

Architecture should be compatible with a future:

Python + FastAPI backend.

For the current hackathon demo, implement the analysis engine locally/in the frontend or through a mock service.

Create a clean service layer so it can later communicate with:

POST /api/analyze-email
POST /api/analyze-headers
GET /api/ip-intelligence
GET /api/domain-intelligence
GET /api/url-intelligence

Do not require the Python backend to run for the demo version.

==================================================
MAIN SYSTEM FLOW
==================================================

Implement this exact conceptual flow:

USER
   ↓
UPLOAD .EML
   ↓
REACT FRONTEND
   ↓
EMAIL PARSER
   ↓
ANALYSIS ENGINE
   ↓
SPF
DKIM
DMARC
   ↓
SENDER ANALYSIS
DOMAIN ANALYSIS
URL ANALYSIS
IP ANALYSIS
ATTACHMENT ANALYSIS
   ↓
THREAT INTELLIGENCE
   ↓
GEOLOCATION
   ↓
IOC EXTRACTION
   ↓
FORENSIC ANALYSIS
   ↓
AI THREAT VERDICT
   ↓
SECURITY RECOMMENDATIONS
   ↓
INVESTIGATION REPORT

==================================================
DESIGN
==================================================

Create a premium cybersecurity/SOC interface.

Style:

- Dark navy/black background
- Professional security dashboard
- Cyan/blue highlights
- Red for critical threats
- Orange for warnings
- Green for safe results
- Glassmorphism cards
- Subtle borders
- Soft shadows
- Professional typography
- Smooth animations
- Responsive design
- Desktop-first

Do NOT make it look like a generic admin dashboard.

The visual feeling should be:

"Enterprise Security Operations Center"

Use subtle animations for:

- file upload
- scanning
- analysis
- threat detection
- risk score
- timeline
- map markers

==================================================
SIDEBAR
==================================================

Create a sidebar with:

MailSentinel AI

Navigation:

1. Dashboard
2. Email Analyzer
3. Threat Intelligence
4. Geolocation
5. Forensic Investigation
6. IOC Explorer
7. Reports
8. Settings

At the bottom:

● SYSTEM ONLINE

DEMO MODE

==================================================
PAGE 1 — DASHBOARD
==================================================

Create a professional SOC dashboard.

Top cards:

Emails Analyzed
Threats Detected
Critical Threats
Suspicious URLs
Suspicious IPs
IOCs Extracted

Use realistic demo numbers.

Example:

1,284 Emails Analyzed
327 Threats Detected
86 Critical Threats
142 Suspicious URLs
73 Suspicious IPs
418 IOCs

Create charts:

1. Threat Distribution

Phishing
Malware
Spam
Credential Theft
Safe

2. Threat Activity

Show suspicious email activity over time.

3. Recent Investigations

Columns:

Email
Threat Type
Risk Score
Severity
Location
Status
Time

Rows should be clickable and open the investigation.

==================================================
PAGE 2 — EMAIL ANALYZER
==================================================

THIS IS THE MOST IMPORTANT PAGE.

Create a beautiful email investigation workspace.

At the top:

"Email Threat Analyzer"

Description:

"Upload an email or analyze a sample to detect phishing, malware, suspicious infrastructure and other threats."

Provide a large drag-and-drop upload area.

Accepted file:

.EML

Show:

"Drag & drop your .EML file here"

Buttons:

Browse File

Try Phishing Demo

Try Malware Demo

Try Safe Email

Also provide:

"Paste Email Content"

with a text editor.

==================================================
EML UPLOAD
==================================================

When a user uploads an .EML file:

1. Read the file.
2. Parse:
   - From
   - To
   - Reply-To
   - Subject
   - Date
   - Message-ID
   - Received headers
   - URLs
   - IP addresses
   - Attachments
3. Display the parsed email.
4. Start analysis.

If parsing fails:

Show a friendly error.

Do not crash.

If the uploaded file is not actually an EML:

Show:

"Invalid email file. Please upload a valid .EML file."

==================================================
ANALYSIS EXPERIENCE
==================================================

When the user clicks:

"ANALYZE EMAIL"

show a realistic animated analysis sequence.

Example:

[✓] Parsing email
[✓] Extracting headers
[✓] Checking sender
[✓] Analyzing SPF
[✓] Analyzing DKIM
[✓] Analyzing DMARC
[✓] Extracting URLs
[✓] Investigating IP addresses
[✓] Checking domain reputation
[✓] Extracting IOCs
[✓] Performing forensic analysis
[✓] Calculating threat score

Then show:

"ANALYSIS COMPLETE"

==================================================
THREAT VERDICT
==================================================

Display a large threat result.

Example:

CRITICAL THREAT

Threat Type:
Credential Phishing

Risk Score:
92 / 100

AI Confidence:
96.8%

Use a large animated circular risk gauge.

Risk levels:

0–30:
LOW

31–60:
MEDIUM

61–80:
HIGH

81–100:
CRITICAL

==================================================
THREAT EXPLANATION
==================================================

Create:

"Why was this email flagged?"

Show detection reasons.

Example:

✓ Suspicious sender domain
✓ Domain resembles a legitimate organization
✓ SPF authentication failed
✓ DKIM authentication failed
✓ DMARC policy failed
✓ Suspicious URL detected
✓ Credential harvesting indicators detected
✓ Urgent/social-engineering language detected
✓ Suspicious originating IP

Each indicator should have:

Icon
Name
Status
Short explanation

==================================================
SPF / DKIM / DMARC
==================================================

Create a dedicated:

"Email Authentication Analysis"

Show three large cards.

SPF

Status:
FAIL

Explanation:
"Sender IP is not authorized by the domain's SPF policy."

DKIM

Status:
FAIL

Explanation:
"Email signature verification failed."

DMARC

Status:
FAIL

Explanation:
"Domain alignment/authentication policy failed."

Also support:

PASS
FAIL
SUSPICIOUS
UNKNOWN

IMPORTANT:

These should be DEMO results in demo mode.

Do not falsely claim that a real external API was called.

Display:

"Demo Intelligence"

when mock results are being used.

==================================================
EMAIL HEADER FORENSICS
==================================================

Create:

"Email Header Forensics"

Display a table:

Header
Value
Analysis

From
attacker@example.com
Suspicious

Reply-To
different@example.com
Suspicious

Return-Path
unknown@example.com
Suspicious

Message-ID
...
Analyzed

Received
IP address
Investigated

SPF
FAIL

DKIM
FAIL

DMARC
FAIL

Create:

"View Raw Headers"

button.

When clicked, show formatted raw headers in a terminal/code-style panel.

==================================================
SENDER INTELLIGENCE
==================================================

Create:

"Sender Intelligence"

Show:

Sender email
Display name
Sender domain
Reply-To
Domain age
Domain reputation
Authentication status
Risk level

Add:

"Domain resembles legitimate organization"

when appropriate.

==================================================
URL ANALYSIS
==================================================

Extract URLs from the email.

Display:

URL
Domain
HTTPS
Redirect
Reputation
Risk

Example:

https://secure-login-example.com/login

Status:
MALICIOUS

Add visual warning if:

- suspicious domain
- URL shortening
- suspicious path
- credential harvesting
- redirects

==================================================
IP INTELLIGENCE
==================================================

Extract IP addresses from email headers.

Display:

IP Address
Reputation
Country
City
ISP
ASN
Risk

Use DEMO intelligence data.

Do not make claims about real individuals.

==================================================
GEOLOCATION PAGE
==================================================

Create a professional interactive map.

Title:

"Threat Origin & Geolocation Intelligence"

Use Leaflet/OpenStreetMap.

Show:

IP address
Country
Region
City
ISP
ASN
Latitude
Longitude
Risk Score

Add a map marker.

Show:

Email
 ↓
Originating IP
 ↓
Geolocation
 ↓
Threat Intelligence

Create an "Origin Analysis" card.

Example demo data:

Country:
Netherlands

City:
Amsterdam

Region:
North Holland

ISP:
Example Network

ASN:
ASXXXXX

Risk:
HIGH

Clearly mark this as:

DEMO GEOLOCATION DATA

Do not imply this identifies a real person.

==================================================
IOC EXPLORER
==================================================

IOC means:

Indicators of Compromise.

Automatically extract:

- IP addresses
- Domains
- URLs
- Email addresses
- File hashes
- Attachment names

Create a searchable table.

Columns:

Type
Value
Reputation
Risk
Source

Allow:

Copy IOC

Search IOC

Filter by type

==================================================
ATTACHMENT ANALYSIS
==================================================

If the email contains attachments:

Display:

File Name
File Type
Size
Hash
Risk
Status

Example:

invoice.pdf

Status:
SUSPICIOUS

Do not execute attachments.

This is static/demo analysis only.

==================================================
FORENSIC INVESTIGATION
==================================================

Create a professional forensic investigation page.

Show:

Investigation ID

Example:

INV-2026-001284

Investigation Status:

COMPLETED

Create a timeline:

10:42:11
Email received

10:42:12
Headers parsed

10:42:13
Sender analyzed

10:42:13
IP extracted

10:42:14
Geolocation identified

10:42:15
URL analyzed

10:42:16
Authentication failure detected

10:42:17
Threat classified

10:42:18
Investigation completed

==================================================
ATTACK CHAIN
==================================================

Create a visual attack chain:

EMAIL
 ↓
SUSPICIOUS SENDER
 ↓
MALICIOUS DOMAIN
 ↓
SUSPICIOUS URL
 ↓
EXTERNAL IP
 ↓
GEOLOCATION
 ↓
THREAT INTELLIGENCE
 ↓
CRITICAL VERDICT

Make it visually impressive.

==================================================
THREAT INTELLIGENCE
==================================================

Create a Threat Intelligence page.

Tabs:

Domain Intelligence
IP Intelligence
URL Intelligence

Domain:

Domain
Age
Registrar
DNS
Reputation
Risk

IP:

IP
Country
ASN
ISP
Reputation
Abuse Score
Risk

URL:

URL
Domain
HTTPS
Redirects
Reputation
Risk

Use demo intelligence when APIs are not connected.

==================================================
AI ANALYSIS ENGINE
==================================================

Create a modular demo analysis engine.

Create:

analyzeEmail(email)

Return structured information:

{
  riskScore,
  threatType,
  severity,
  confidence,
  indicators,
  senderAnalysis,
  authenticationAnalysis,
  urlAnalysis,
  ipAnalysis,
  geolocation,
  iocs,
  attachments,
  recommendations,
  timeline
}

Risk score should be calculated from multiple signals.

For example:

Suspicious URL:
+25

SPF failure:
+15

DKIM failure:
+15

DMARC failure:
+15

Suspicious sender:
+10

Credential phishing language:
+15

Suspicious attachment:
+20

Malicious domain:
+25

Cap score at 100.

Use explainable rules.

The UI should say:

"AI-Assisted Demo Analysis"

NOT:

"Certified AI detection"

Do not falsely claim to use a real machine learning model.

==================================================
DEMO SCENARIOS
==================================================

Create THREE fully working demo scenarios.

------------------------------------------
DEMO 1 — PHISHING
------------------------------------------

Subject:

"URGENT: Your University Account Will Be Suspended"

Risk:

92 / 100

Threat:

Credential Phishing

Severity:

CRITICAL

Indicators:

- SPF FAIL
- DKIM FAIL
- DMARC FAIL
- Suspicious sender
- Suspicious domain
- Malicious URL
- Credential harvesting
- Social engineering

------------------------------------------
DEMO 2 — MALWARE
------------------------------------------

Subject:

"Invoice Attached — Payment Required"

Risk:

87 / 100

Threat:

Malware Delivery

Indicators:

- Suspicious attachment
- Unknown sender
- Suspicious domain
- Suspicious hash
- External IP

------------------------------------------
DEMO 3 — SAFE
------------------------------------------

Subject:

"University Event Registration Confirmation"

Risk:

12 / 100

Threat:

SAFE

Most authentication checks:

PASS

No malicious URLs.

No suspicious attachment.

No suspicious infrastructure.

==================================================
DEMO BUTTONS
==================================================

On Email Analyzer create three prominent buttons:

[ TRY PHISHING DEMO ]

[ TRY MALWARE DEMO ]

[ TRY SAFE EMAIL ]

When clicked:

1. Load sample email
2. Automatically populate the email viewer
3. Run analysis
4. Show analysis animation
5. Display complete results

This must work reliably.

This is the main feature judges will use.

==================================================
SECURITY RECOMMENDATIONS
==================================================

After analysis show:

"Recommended Security Actions"

For a critical threat:

1. Quarantine Email
2. Block Malicious Domain
3. Block Suspicious IP
4. Search for Similar Emails
5. Reset Potentially Exposed Credentials
6. Notify Security Administrator
7. Add IOC to Blocklist

These are DEMO actions.

When clicked:

Show toast:

"Demo security action executed."

Do not actually block anything or modify external systems.

==================================================
REPORTS
==================================================

Create:

"Generate Investigation Report"

The report should include:

Investigation ID
Timestamp
Threat Verdict
Risk Score
Confidence
Sender
Recipient
Subject
SPF
DKIM
DMARC
Domain Intelligence
URL Intelligence
IP Intelligence
Geolocation
Extracted IOCs
Attachments
Forensic Timeline
Attack Chain
Recommended Actions

Create a professional report view.

Add:

Print Report

button.

==================================================
SETTINGS
==================================================

Create a simple Settings page.

Show:

Analysis Mode:

Demo Intelligence

API Integration:

Not Connected

Backend:

Demo Mode

System Status:

Online

Future integrations:

SPF API
DKIM API
DMARC API
IP Geolocation API
Threat Intelligence API
Virus/URL Reputation API

Do not require these integrations for the demo.

==================================================
BACKEND ARCHITECTURE
==================================================

Although the first version must work without backend setup, organize the code so a Python FastAPI backend can be connected later.

Expected future architecture:

Frontend:
React / Next.js

↓

FastAPI Backend

↓

Email Parser

↓

SPF API
DKIM API
DMARC API

↓

Threat Intelligence

↓

Analysis Engine

↓

Geolocation

↓

Forensic Intelligence

↓

Frontend Dashboard

Create a service abstraction such as:

emailAnalysisService

so that demo/mock analysis can later be replaced by:

/api/analyze-email

Do NOT put secret API keys in React.

==================================================
ERROR HANDLING
==================================================

The application must gracefully handle:

- Invalid file
- Empty email
- Missing headers
- No URLs
- No IP addresses
- No attachments
- Analysis failure
- Unknown domain
- Unknown IP
- API unavailable

Never show a blank screen.

Never crash.

If information is unavailable, show:

UNKNOWN

rather than inventing a result.

==================================================
IMPORTANT UX
==================================================

The judge should be able to understand the application within 30 seconds.

The main dashboard should communicate:

"Upload suspicious email → Analyze → Understand threat → Investigate origin → Extract evidence → Generate report"

Add a "Quick Start" panel:

STEP 1
Upload an .EML

STEP 2
Run AI Analysis

STEP 3
Investigate Threat

STEP 4
View Geolocation

STEP 5
Explore IOCs

STEP 6
Generate Report

==================================================
LANDING / EMPTY STATE
==================================================

If no email has been analyzed yet, show:

"Start Your Investigation"

with:

Upload .EML

or

Try Demo Investigation

Make the demo buttons highly visible.

==================================================
FINAL QUALITY REQUIREMENTS
==================================================

Before finishing:

- Make sure every route works.
- Make sure navigation works.
- Make sure demo buttons work.
- Make sure email analysis works.
- Make sure risk score appears.
- Make sure charts render.
- Make sure map renders.
- Make sure IOC extraction works.
- Make sure forensic timeline renders.
- Make sure report generation works.
- Make sure responsive layout works.
- Make sure there are no console errors.
- Make sure there are no broken imports.
- Make sure no API key is required.
- Make sure the application works immediately in DEMO MODE.

DO NOT over-engineer the first version.

PRIORITY:

1. Working demo
2. Excellent UI
3. Email upload
4. Demo analysis
5. Threat verdict
6. SPF/DKIM/DMARC visualization
7. IOC extraction
8. Geolocation
9. Forensics
10. Report

Build the application now.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://mailsentinelai.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/c1437dff-e5fe-4bb4-9cf9-f94d9e7032d4).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
