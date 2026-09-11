export interface SampleEmail {
  id: "phishing" | "malware" | "safe";
  label: string;
  subject: string;
  description: string;
  raw: string;
}

const phishing = `Return-Path: <billing@university-secure-verify.top>
Received: from mx-out.university-secure-verify.top (mx-out.university-secure-verify.top [185.220.101.47])
	by mail.univ.edu (Postfix) with ESMTPS id 4A21B3F2
	for <manu.dhaked@univ.edu>; Wed, 9 Sep 2026 10:42:11 +0000 (UTC)
Received: from localhost (unknown [45.132.192.18])
	by mx-out.university-secure-verify.top with SMTP id 77ac21
	for <manu.dhaked@univ.edu>; Wed, 9 Sep 2026 10:42:09 +0000 (UTC)
Authentication-Results: mail.univ.edu; spf=fail smtp.mailfrom=university-secure-verify.top; dkim=fail header.d=university-secure-verify.top; dmarc=fail (p=none) header.from=university-secure-verify.top
Received-SPF: fail (mail.univ.edu: domain of university-secure-verify.top does not designate 185.220.101.47 as permitted sender)
From: "University IT Helpdesk" <it-helpdesk@university-secure-verify.top>
Reply-To: recovery.desk@mail-support-relay.xyz
To: manu.dhaked@univ.edu
Subject: URGENT: Your University Account Will Be Suspended
Date: Wed, 9 Sep 2026 10:42:08 +0000
Message-ID: <8f21a0c4-urgent-account@university-secure-verify.top>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear Student,

ACTION REQUIRED. Our records show unusual sign-in activity on your university
account. Your account will be suspended within 24 hours unless you verify your
account immediately.

Please sign in to verify your identity here:
https://secure-login-university-portal.top/verify?redirect=http://45.132.192.18/collect

Failure to comply will result in permanent loss of access to email, library and
examination services.

University IT Helpdesk
Do not reply to this automated message.
`;

const malware = `Return-Path: <accounts@invoice-billing-dept.click>
Received: from smtp7.invoice-billing-dept.click (smtp7.invoice-billing-dept.click [91.219.236.90])
	by mail.univ.edu (Postfix) with ESMTPS id 91C4D0A1
	for <finance@univ.edu>; Wed, 9 Sep 2026 09:14:52 +0000 (UTC)
Authentication-Results: mail.univ.edu; spf=fail smtp.mailfrom=invoice-billing-dept.click; dkim=fail header.d=invoice-billing-dept.click; dmarc=fail header.from=invoice-billing-dept.click
From: "Accounts Payable" <accounts@invoice-billing-dept.click>
Reply-To: accounts.remit@invoice-billing-dept.click
To: finance@univ.edu
Subject: Invoice Attached - Payment Required
Date: Wed, 9 Sep 2026 09:14:50 +0000
Message-ID: <inv-99213-payment@invoice-billing-dept.click>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_9921"

------=_Part_9921
Content-Type: text/plain; charset="utf-8"

Hello,

Please find attached invoice INV-99213. Payment is required immediately to avoid
service interruption. Open the attached document and enable content to view the
payment details.

Accounts Payable

------=_Part_9921
Content-Type: application/octet-stream; name="invoice_99213.pdf.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice_99213.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUg
cnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAGSGBQBkZW1vLXBheWxvYWQtc2FtcGxlLWZv
------=_Part_9921
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="remittance.xlsm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="remittance.xlsm"

UEsDBBQABgAIAAAAIQBiDemoLXNtIG1hY3JvIHNhbXBsZSBmb3IgYW5hbHlzaXMgb25seQAAAAA=
------=_Part_9921--
`;

const safe = `Return-Path: <events@univ.edu>
Received: from mail.univ.edu (mail.univ.edu [203.0.113.24])
	by mx.univ.edu (Postfix) with ESMTPS id 2B77A11
	for <manu.dhaked@univ.edu>; Tue, 8 Sep 2026 14:03:11 +0000 (UTC)
Authentication-Results: mx.univ.edu; spf=pass smtp.mailfrom=univ.edu; dkim=pass header.d=univ.edu; dmarc=pass header.from=univ.edu
From: "University Events Office" <events@univ.edu>
To: manu.dhaked@univ.edu
Subject: University Event Registration Confirmation
Date: Tue, 8 Sep 2026 14:03:09 +0000
Message-ID: <event-reg-55120@univ.edu>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Manu,

Your registration for the Annual Innovation Symposium on 21 September is
confirmed. Your seat number is B-114 and the session begins at 09:30 in the
Central Auditorium.

You can review the schedule on the university site:
https://univ.edu/events/innovation-symposium

Kind regards,
University Events Office
`;

export const SAMPLE_EMAILS: SampleEmail[] = [
  {
    id: "phishing",
    label: "Try Phishing Demo",
    subject: "URGENT: Your University Account Will Be Suspended",
    description: "Credential phishing with failed authentication and a lookalike domain.",
    raw: phishing,
  },
  {
    id: "malware",
    label: "Try Malware Demo",
    subject: "Invoice Attached - Payment Required",
    description: "Malware delivery through a disguised executable and macro workbook.",
    raw: malware,
  },
  {
    id: "safe",
    label: "Try Safe Email",
    subject: "University Event Registration Confirmation",
    description: "Legitimate internal message that passes all authentication checks.",
    raw: safe,
  },
];

export function getSample(id: SampleEmail["id"]): SampleEmail {
  return SAMPLE_EMAILS.find((s) => s.id === id) ?? SAMPLE_EMAILS[0]!;
}
