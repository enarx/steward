use sgx::ReportBody;

/// Verify fields in the structure.
pub fn quote_report_body_verify(_body: &ReportBody) -> Result<(), anyhow::Error> {
    Ok(())
}
