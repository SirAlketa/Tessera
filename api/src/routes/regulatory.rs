//! FATF Travel Rule and MAS regulatory reporting (issue #72).
//!
//! `POST /v1/admin/regulatory/fatf-travel-rule` describes the Travel Rule
//! report for transfers above USD 1 000 in an inclusive date range. The report
//! is formatted as ISO 20022 `pacs.008` XML. Each transaction carries the
//! originator and beneficiary VASP LEI, the USD-equivalent amount, the asset
//! type and the Stellar transaction hash. In `mas` mode each transaction also
//! carries the Singapore MAS-only fields: the Unique Entity Number (UEN) and
//! the risk rating.
//!
//! Not yet connected (see the pull request notes): the transfer source, the
//! VASP registry lookup from the `compliance` contract, Ed25519 signing via
//! `services/mpc-signer/`, IPFS storage and the 1 request/hour admin limit.
#![allow(dead_code)]

use axum::Json;
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use super::ApiError;

/// Transfers strictly above this USD-equivalent amount are reportable.
pub const TRAVEL_RULE_THRESHOLD_USD: f64 = 1_000.0;

const PACS008_NAMESPACE: &str = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08";

/// Report flavour. `Mas` adds the Singapore MAS-only fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportMode {
    #[default]
    Standard,
    Mas,
}

/// Request body for `POST /v1/admin/regulatory/fatf-travel-rule`.
#[derive(Debug, Clone, Deserialize)]
pub struct TravelRuleRequest {
    /// Inclusive start date, `YYYY-MM-DD`.
    pub start_date: String,
    /// Inclusive end date, `YYYY-MM-DD`.
    pub end_date: String,
    #[serde(default)]
    pub mode: ReportMode,
}

/// MAS-only fields attached to a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasFields {
    pub uen: String,
    pub risk_rating: String,
}

/// One transfer as needed for the Travel Rule report.
#[derive(Debug, Clone, PartialEq)]
pub struct TravelRuleTransfer {
    pub transfer_id: String,
    pub originator_vasp_lei: String,
    pub beneficiary_vasp_lei: String,
    pub amount_usd: f64,
    pub asset_type: String,
    pub stellar_tx_hash: String,
    pub settled_on: NaiveDate,
    pub mas: Option<MasFields>,
}

/// A Legal Entity Identifier is 20 upper-case alphanumeric characters (ISO 17442).
pub fn is_valid_lei(lei: &str) -> bool {
    lei.len() == 20 && lei.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Travel Rule applies only to transfers strictly above the threshold.
pub fn is_reportable(transfer: &TravelRuleTransfer) -> bool {
    transfer.amount_usd > TRAVEL_RULE_THRESHOLD_USD
}

/// Parses and orders an inclusive `YYYY-MM-DD` date range.
pub fn parse_date_range(start: &str, end: &str) -> Result<(NaiveDate, NaiveDate), ApiError> {
    let start_date = NaiveDate::parse_from_str(start, "%Y-%m-%d")
        .map_err(|_| ApiError::BadRequest("start_date must be YYYY-MM-DD".to_string()))?;
    let end_date = NaiveDate::parse_from_str(end, "%Y-%m-%d")
        .map_err(|_| ApiError::BadRequest("end_date must be YYYY-MM-DD".to_string()))?;
    if start_date > end_date {
        return Err(ApiError::BadRequest(
            "start_date must not be after end_date".to_string(),
        ));
    }
    Ok((start_date, end_date))
}

fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn push_element(out: &mut String, indent: usize, name: &str, value: &str) {
    out.push_str(&format!(
        "{}<{name}>{}</{name}>\n",
        "  ".repeat(indent),
        escape_xml(value)
    ));
}

fn push_agent(out: &mut String, role: &str, lei: &str) {
    out.push_str(&format!(
        "      <{role}>\n        <FinInstnId>\n          <LEI>{}</LEI>\n        </FinInstnId>\n      </{role}>\n",
        escape_xml(lei)
    ));
}

fn push_transaction(out: &mut String, transfer: &TravelRuleTransfer, mode: ReportMode) {
    out.push_str("    <CdtTrfTxInf>\n      <PmtId>\n");
    push_element(out, 4, "EndToEndId", &transfer.transfer_id);
    push_element(out, 4, "TxId", &transfer.stellar_tx_hash);
    out.push_str("      </PmtId>\n");
    out.push_str(&format!(
        "      <IntrBkSttlmAmt Ccy=\"USD\">{:.2}</IntrBkSttlmAmt>\n",
        transfer.amount_usd
    ));
    push_element(out, 3, "IntrBkSttlmDt", &transfer.settled_on.to_string());
    push_agent(out, "DbtrAgt", &transfer.originator_vasp_lei);
    push_agent(out, "CdtrAgt", &transfer.beneficiary_vasp_lei);
    out.push_str("      <RmtInf>\n");
    push_element(out, 4, "Ustrd", &format!("asset type: {}", transfer.asset_type));
    out.push_str("      </RmtInf>\n");
    if mode == ReportMode::Mas {
        if let Some(mas) = &transfer.mas {
            out.push_str("      <SplmtryData>\n        <Envlp>\n          <MAS>\n");
            push_element(out, 6, "UEN", &mas.uen);
            push_element(out, 6, "RiskRating", &mas.risk_rating);
            out.push_str("          </MAS>\n        </Envlp>\n      </SplmtryData>\n");
        }
    }
    out.push_str("    </CdtTrfTxInf>\n");
}

/// Builds the `pacs.008` document for all reportable transfers.
///
/// Transfers at or below the threshold are skipped. Returns an error when a
/// reportable transfer has a malformed LEI, or when `Mas` mode is requested
/// and a reportable transfer has no MAS fields.
pub fn build_pacs008(
    transfers: &[TravelRuleTransfer],
    mode: ReportMode,
    message_id: &str,
    created_at: &str,
) -> Result<String, String> {
    let reportable: Vec<&TravelRuleTransfer> =
        transfers.iter().filter(|t| is_reportable(t)).collect();

    for transfer in &reportable {
        if !is_valid_lei(&transfer.originator_vasp_lei) {
            return Err(format!(
                "transfer {} has an invalid originator VASP LEI",
                transfer.transfer_id
            ));
        }
        if !is_valid_lei(&transfer.beneficiary_vasp_lei) {
            return Err(format!(
                "transfer {} has an invalid beneficiary VASP LEI",
                transfer.transfer_id
            ));
        }
        if mode == ReportMode::Mas && transfer.mas.is_none() {
            return Err(format!(
                "transfer {} is missing MAS-only fields",
                transfer.transfer_id
            ));
        }
    }

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!("<Document xmlns=\"{PACS008_NAMESPACE}\">\n"));
    out.push_str("  <FIToFICstmrCdtTrf>\n    <GrpHdr>\n");
    push_element(&mut out, 3, "MsgId", message_id);
    push_element(&mut out, 3, "CreDtTm", created_at);
    push_element(&mut out, 3, "NbOfTxs", &reportable.len().to_string());
    out.push_str("      <SttlmInf>\n");
    push_element(&mut out, 4, "SttlmMtd", "INDA");
    out.push_str("      </SttlmInf>\n    </GrpHdr>\n");
    for transfer in reportable {
        push_transaction(&mut out, transfer, mode);
    }
    out.push_str("  </FIToFICstmrCdtTrf>\n</Document>\n");
    Ok(out)
}

/// `POST /v1/admin/regulatory/fatf-travel-rule`.
///
/// Validates the request. The transfer source is not connected yet, so a valid
/// request is answered with 503 rather than an empty report.
pub async fn fatf_travel_rule(
    Json(request): Json<TravelRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _range = parse_date_range(&request.start_date, &request.end_date)?;
    Err(ApiError::Unavailable(
        "transfer source for the Travel Rule report is not connected yet".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEI_A: &str = "529900T8BM49AURSDO55";
    const LEI_B: &str = "5493001KJTIIGC8Y1R12";

    fn transfer(id: &str, amount: f64, mas: Option<MasFields>) -> TravelRuleTransfer {
        TravelRuleTransfer {
            transfer_id: id.to_string(),
            originator_vasp_lei: LEI_A.to_string(),
            beneficiary_vasp_lei: LEI_B.to_string(),
            amount_usd: amount,
            asset_type: "USDC".to_string(),
            stellar_tx_hash: "abc123".to_string(),
            settled_on: NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            mas,
        }
    }

    fn mas() -> Option<MasFields> {
        Some(MasFields {
            uen: "201912345K".to_string(),
            risk_rating: "medium".to_string(),
        })
    }

    #[test]
    fn threshold_is_strictly_above_one_thousand() {
        assert!(!is_reportable(&transfer("a", 1_000.0, None)));
        assert!(is_reportable(&transfer("b", 1_000.01, None)));
    }

    #[test]
    fn lei_must_be_twenty_uppercase_alphanumerics() {
        assert!(is_valid_lei(LEI_A));
        assert!(!is_valid_lei("529900t8bm49aursdo55"));
        assert!(!is_valid_lei("529900T8BM49AURSDO5"));
    }

    #[test]
    fn date_range_is_validated() {
        assert!(parse_date_range("2026-01-01", "2026-01-31").is_ok());
        assert!(parse_date_range("2026-02-01", "2026-01-31").is_err());
        assert!(parse_date_range("01/02/2026", "2026-01-31").is_err());
    }

    #[test]
    fn standard_report_skips_small_transfers_and_omits_mas_fields() {
        let transfers = vec![transfer("small", 500.0, mas()), transfer("big", 2_500.0, mas())];
        let xml = build_pacs008(&transfers, ReportMode::Standard, "MSG-1", "2026-01-31T00:00:00Z")
            .unwrap();
        assert!(xml.contains("<NbOfTxs>1</NbOfTxs>"));
        assert!(xml.contains("<EndToEndId>big</EndToEndId>"));
        assert!(!xml.contains("<EndToEndId>small</EndToEndId>"));
        assert!(xml.contains(&format!("<LEI>{LEI_A}</LEI>")));
        assert!(xml.contains("<TxId>abc123</TxId>"));
        assert!(xml.contains("<IntrBkSttlmAmt Ccy=\"USD\">2500.00</IntrBkSttlmAmt>"));
        assert!(!xml.contains("<MAS>"));
    }

    #[test]
    fn mas_mode_adds_uen_and_risk_rating() {
        let transfers = vec![transfer("big", 2_500.0, mas())];
        let xml =
            build_pacs008(&transfers, ReportMode::Mas, "MSG-2", "2026-01-31T00:00:00Z").unwrap();
        assert!(xml.contains("<UEN>201912345K</UEN>"));
        assert!(xml.contains("<RiskRating>medium</RiskRating>"));
    }

    #[test]
    fn mas_mode_requires_mas_fields_on_reportable_transfers() {
        let transfers = vec![transfer("big", 2_500.0, None)];
        let result = build_pacs008(&transfers, ReportMode::Mas, "MSG-3", "2026-01-31T00:00:00Z");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_lei_is_rejected() {
        let mut bad = transfer("big", 2_500.0, None);
        bad.beneficiary_vasp_lei = "not-a-lei".to_string();
        let result = build_pacs008(&[bad], ReportMode::Standard, "MSG-4", "2026-01-31T00:00:00Z");
        assert!(result.is_err());
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        assert_eq!(escape_xml("a<b&\"c\""), "a&lt;b&amp;&quot;c&quot;");
    }
}
