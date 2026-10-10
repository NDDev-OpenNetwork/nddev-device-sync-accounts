use nddev_device_sync_accounts::NativeSessionStore;

#[tokio::test]
#[ignore = "requires the user's actual unlocked native credential service"]
async fn owned_ephemeral_entry_round_trips_and_is_deleted() {
    let scope = format!("https://nds-test-{}.invalid/", uuid::Uuid::new_v4());
    let store = NativeSessionStore::for_endpoint(&scope).unwrap();
    assert!(store.read().await.unwrap().is_none());
    let value = uuid::Uuid::new_v4().to_string();
    store.write(value.as_bytes()).await.unwrap();
    let restored = NativeSessionStore::for_endpoint(&scope).unwrap();
    let read = restored.read().await;
    let deleted = restored.delete().await;
    deleted.unwrap();
    assert_eq!(read.unwrap().unwrap().as_slice(), value.as_bytes());
    assert!(store.read().await.unwrap().is_none());
}
