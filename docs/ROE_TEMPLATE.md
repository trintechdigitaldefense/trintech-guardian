# Rules of Engagement — TrinTech-Guardian Deployment

**TrinTech Digital Defense** · Trinidad & Tobago  
**Document version:** 1.3.0  
**Classification:** Confidential — Client Engagement

---

## 1. Parties

| Role | Details |
|------|---------|
| Provider | TrinTech Digital Defense |
| Client | _________________________________ |
| Engagement ID | _________________________________ |
| Primary contact (Client) | _________________________________ |
| Primary contact (TrinTech) | Jason Ramdharry · +1-868-362-0679 |

## 2. Scope

Guardian will be deployed **only** on systems and network segments explicitly listed below:

| Asset / Segment | IP / Range | Notes |
|-----------------|------------|-------|
| | | |
| | | |

**Out of scope:** Any system, cloud account, or network not listed above.

## 3. Authorized Activities

- [ ] Run Guardian in **dry-run** mode (detection + logging only)
- [ ] Run Guardian in **live containment** mode (timed firewall isolation)
- [ ] Deploy deception canaries on agreed ports
- [ ] Perform process scanning on the monitored host(s)
- [ ] Generate forensic JSON and client PDF/HTML reports

## 4. Prohibited Activities

- Scanning or interacting with systems outside the listed scope
- Permanent irreversible changes without written approval
- Exfiltration of client data beyond engagement artifacts
- Use of Guardian findings against third parties

## 5. Containment Policy

| Mode | Behaviour |
|------|-----------|
| Dry-run | No firewall changes. Events logged and reported only. |
| Live | Temporary DROP rules. Default block duration: **30 minutes** (configurable). |

Client may request immediate release of any blocked address via WhatsApp/email.

## 6. Data Handling

- Incident reports retained for **90 days** unless Client requests earlier destruction
- Covered by mutual NDA

## 7. Emergency Stop

Client may request immediate shutdown at any time. TrinTech will disable within 15 minutes of confirmed request during business hours.

## 8. Legal

Defensive activities authorized by the Client. Reference: Trinidad & Tobago Cybercrime Act.

## 9. Signatures

| | Name | Signature | Date |
|---|------|-----------|------|
| **Client** | | | |
| **TrinTech** | | | |
