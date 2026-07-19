use procjail::{probe_capabilities, Strategy};

#[test]
fn probe_returns_valid_strategy() {
    let level = probe_capabilities();
    // Strategy must be one of the valid variants.
    let valid = matches!(
        level.best_strategy,
        Strategy::Unshare | Strategy::Bubblewrap | Strategy::Firejail | Strategy::RlimitsOnly
    );
    assert!(valid, "invalid strategy: {:?}", level.best_strategy);
}

#[test]
fn strategy_consistency() {
    let level = probe_capabilities();
    if level.has_unshare {
        assert_eq!(level.best_strategy, Strategy::Unshare);
    }
    if !level.has_unshare && level.has_bubblewrap {
        assert_eq!(level.best_strategy, Strategy::Bubblewrap);
    }
}
