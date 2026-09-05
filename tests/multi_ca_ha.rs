//! Real local-CA readiness probes, failure and recovery through the HA worker.
#[allow(dead_code)]
mod common;
use std::sync::Arc;

#[tokio::test]
async fn health_worker_detects_key_loss_and_recovery() {
    let ca = common::TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let primary_key = dir.path().join("primary.key");
    let secondary_key = dir.path().join("secondary.key");
    std::fs::write(&primary_key, &ca.key_pem).unwrap();
    std::fs::write(&secondary_key, &ca.key_pem).unwrap();
    let mut config = common::test_config();
    config.cas[0].id = "primary".into();
    config.cas[0].is_default = true;
    config.cas[0].key_file = primary_key.to_str().unwrap().into();
    let mut second = config.cas[0].clone();
    second.id = "secondary".into();
    second.is_default = false;
    second.key_file = secondary_key.to_str().unwrap().into();
    config.cas.push(second);
    config.ha = Some(toml::from_str("enabled = true\nprobe_interval_secs = 1\nprobe_timeout_secs = 1\nfailure_threshold = 1\ncooldown_secs = 1").unwrap());
    let mut cas = indexmap::IndexMap::new();
    cas.insert("primary".into(), Arc::new(ca.to_ca_state("primary")));
    cas.insert("secondary".into(), Arc::new(ca.to_ca_state("secondary")));
    let manager = kipuka::ha::build_manager(Arc::new(config), Arc::new(cas), None).unwrap();
    let worker = manager.start().await;
    assert_eq!(manager.pool().select().unwrap().id.0, "primary");
    let hidden_key = dir.path().join("primary.unavailable");
    std::fs::rename(&primary_key, &hidden_key).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if manager.pool().select().unwrap().id.0 == "secondary" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(manager.pool().select_allowed(&["primary".into()]).is_none());
    std::fs::rename(&hidden_key, &primary_key).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if manager.pool().select().unwrap().id.0 == "primary" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    manager.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
}
