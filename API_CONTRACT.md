# CyberGuard AI - Compliance Gap Module API Contract

This document outlines the REST/GraphQL schema contract required to transition the Compliance Gap Analysis module from frontend mock data to live backend data.

## 1. Compliance Gap Analysis Endpoint

**Endpoint:** `GET /api/v1/compliance/gap-analysis`
**Method:** `GET`
**Description:** Retrieves full compliance scorecard, gap analysis, evidence linkage, and remediation workflows across frameworks (NIST CSF 2.0, ISO 27001:2022, RBI, SEBI).

### Response Payload (JSON)

```json
{
  "overall_compliance_score": 41.6,
  "active_gaps_count": 89,
  "last_assessed": "2026-09-24T00:00:00Z",
  "next_scheduled_review": "2026-10-24T00:00:00Z",
  "nist_csf_functions": {
    "IDENTIFY": {
      "coverage_pct": 46.4,
      "controls_addressed": 13,
      "total_controls": 28,
      "findings_mapped": 22,
      "status": "GAP",
      "risk_exposure_usd": 790836,
      "extended": {
        "ownerRole": "IT Infrastructure Lead",
        "targetRemediationDate": "2026-12-01",
        "maturityLevel": 2,
        "treatmentDecision": "Mitigate",
        "remediationStatus": "Open",
        "sle": 150000,
        "aro": 5.27,
        "evidence": [
          {
            "type": "Log Export",
            "dateCollected": "2026-09-01",
            "reviewer": "A. Auditor",
            "link": "https://siem.corp/reports/id-123"
          }
        ]
      }
    },
    // ... PROTECT, DETECT, RESPOND, RECOVER
  },
  "iso_27001_controls": {
    "A.6 People Controls": {
      "coverage_pct": 25.0,
      "controls_addressed": 2,
      "total_controls": 8,
      "status": "GAP",
      "extended": {
        "ownerRole": "HR Security Lead",
        "targetRemediationDate": "2026-11-15",
        "maturityLevel": 2,
        "treatmentDecision": "Mitigate",
        "remediationStatus": "In Progress",
        "sle": null,
        "aro": null,
        "evidence": [
          {
            "type": "Policy Document",
            "dateCollected": "2026-09-10",
            "reviewer": "J. Auditor",
            "link": "https://intranet.corp/policies/hr-sec-v2"
          },
          {
            "type": "Interview Note",
            "dateCollected": "2026-09-12",
            "reviewer": "M. Compliance",
            "link": "https://jira.corp/SEC-9921"
          }
        ]
      }
    }
    // ... A.5, A.7, etc.
  },
  "rbi_framework": {
    "status": "PENDING_MAPPING",
    "message": "RBI Cybersecurity Framework mapping is currently pending. Control library integration required."
  },
  "sebi_cscrf": {
    "status": "PENDING_MAPPING",
    "message": "SEBI CSCRF mapping is currently pending. Control library integration required."
  }
}
```

## 2. Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `extended.ownerRole` | `string` | Role-based ownership (e.g., "HR Security Lead", "CISO"). No individual names. |
| `extended.targetRemediationDate` | `string(ISO-8601)` \| `null` | Planned date for gap closure. |
| `extended.maturityLevel` | `int (0-5)` | CMMI Maturity Scale (0: Not Implemented, 1: Initial, 2: Developing, 3: Defined, 4: Managed, 5: Optimized). |
| `extended.treatmentDecision` | `enum` | Action plan: `Mitigate`, `Accept`, `Transfer`, `Avoid`, or `null`. |
| `extended.remediationStatus` | `enum` | Workflow state: `Open`, `In Progress`, `Remediated`, `Verified`, or `null`. |
| `extended.sle` | `number` \| `null` | Single Loss Expectancy (USD). Null triggers "Illustrative" flag. |
| `extended.aro` | `number` \| `null` | Annualized Rate of Occurrence. Null triggers "Illustrative" flag. |
| `evidence[].type` | `enum` | Type of proof: `Policy Document`, `Log Export`, `Screenshot`, `Interview Note`. |
| `evidence[].dateCollected` | `string(ISO-8601)` | Timestamp when evidence was gathered. |
| `evidence[].reviewer` | `string` | Name/ID of the assessor who validated the evidence. |
| `evidence[].link` | `string(URL)` | Deep link to the evidence artifact (Jira, SharePoint, SIEM). |

## 3. Data Integrity & Validation Rules
- **Maturity-Bounded Scoring:** A control category cannot have 100% coverage if its `maturityLevel` is < 4 (Managed) and it lacks valid `evidence`. The backend MUST recalculate or cap scores based on maturity.
- **Risk Calculation:** If `sle` and `aro` are provided, the frontend will derive `ALE = sle * aro`. If either is `null`, the frontend relies on the backend's heuristic `risk_exposure_usd` and explicitly flags the UI as "Illustrative - Asset valuation pending".
