//! Trace-specific receipt counts; events retain their full-count contract.
use crate::observability_wire as wire;
pub(super) fn accepted_count(
    trace: bool,
    count: u32,
    receipt: &wire::IngressReceipt,
) -> Option<i64> {
    if !matches!(receipt.export_mode, wire::ExportMode::Enabled)
        || receipt.accepted < 0
        || receipt.duplicates < 0
    {
        return None;
    }
    let accepted = i64::from(receipt.accepted);
    let duplicates = i64::from(receipt.duplicates);
    let count = i64::from(count);
    if trace {
        (duplicates == 0 && accepted <= count).then_some(accepted)
    } else {
        (accepted + duplicates == count).then_some(count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_and_event_receipts_keep_distinct_count_and_freshness_rules() {
        for count in 1..=32 {
            for accepted in 0..=count {
                let receipt = wire::IngressReceipt {
                    accepted,
                    duplicates: 0,
                    export_mode: wire::ExportMode::Enabled,
                };
                let value = accepted_count(true, count as u32, &receipt).unwrap();
                assert_eq!(value, i64::from(accepted));
                assert_eq!(value == i64::from(count), accepted == count);
                assert_eq!(
                    accepted_count(false, count as u32, &receipt).is_some(),
                    accepted == count
                );
            }
            let event = wire::IngressReceipt {
                accepted: 0,
                duplicates: count,
                export_mode: wire::ExportMode::Enabled,
            };
            assert_eq!(
                accepted_count(false, count as u32, &event),
                Some(i64::from(count))
            );
            assert_eq!(accepted_count(true, count as u32, &event), None);
        }
        for (accepted, duplicates) in [(-1, 0), (3, 0), (0, -1), (1, 1)] {
            let receipt = wire::IngressReceipt {
                accepted,
                duplicates,
                export_mode: wire::ExportMode::Enabled,
            };
            assert_eq!(accepted_count(true, 2, &receipt), None);
        }
    }
}
