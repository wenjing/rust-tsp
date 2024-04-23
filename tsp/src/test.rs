use crate::AsyncStore;

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_direct_mode() {
    tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
        .await
        .unwrap();

    // bob database
    let mut bob_db = AsyncStore::new();
    bob_db
        .add_private_vid_from_file("test/bob.json")
        .await
        .unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    alice_db
        .add_private_vid_from_file("test/alice.json")
        .await
        .unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // send a message
    alice_db
        .send(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await
        .unwrap();

    // receive a message
    let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
        bobs_messages.recv().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a generic message")
    };

    assert_eq!(message, b"hello world");
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_nested_mode() {
    tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
        .await
        .unwrap();

    // bob database
    let mut bob_db = AsyncStore::new();
    bob_db
        .add_private_vid_from_file("test/bob.json")
        .await
        .unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    alice_db
        .add_private_vid_from_file("test/alice.json")
        .await
        .unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // create nested id's
    let nested_bob_vid = bob_db
        .create_private_nested_vid("did:web:did.tsp-test.org:user:bob", None)
        .unwrap();

    // receive a messages on inner vid
    let mut bobs_inner_messages = bob_db.receive(&nested_bob_vid).await.unwrap();

    let nested_alice_vid = alice_db
        .create_private_nested_vid("did:web:did.tsp-test.org:user:alice", Some(&nested_bob_vid))
        .unwrap();

    alice_db
        .verify_vid_with_parent(
            &nested_bob_vid,
            "did:web:did.tsp-test.org:user:bob",
            Some(&nested_alice_vid),
        )
        .await
        .unwrap();

    bob_db.verify_vid(&nested_alice_vid).await.unwrap();

    // send a message using inner vid
    alice_db
        .send_nested(
            &nested_bob_vid,
            Some(b"extra non-confidential data"),
            b"hello nested world",
        )
        .await
        .unwrap();

    // receive message using inner vid
    let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
        bobs_inner_messages.recv().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a generic message inner")
    };

    assert_eq!(message, b"hello nested world".to_vec());
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_routed_mode() {
    use tsp_definitions::VerifiedVid;
    tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
        .await
        .unwrap();

    let mut bob_db = AsyncStore::new();
    bob_db
        .add_private_vid_from_file("test/bob.json")
        .await
        .unwrap();

    let mut alice_db = AsyncStore::new();
    alice_db
        .add_private_vid_from_file("test/alice.json")
        .await
        .unwrap();

    // inform bob about alice
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // let bob listen as an intermediary
    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // inform alice about the nodes
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();
    alice_db
        .set_route_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            &[
                "did:web:did.tsp-test.org:user:bob",
                "did:web:did.tsp-test.org:user:alice",
                "did:web:hidden.web:user:realbob",
            ],
        )
        .unwrap();
    alice_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:bob",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();
    alice_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();

    // let alice send a message via bob to herself
    alice_db
        .send_routed(
            "did:web:did.tsp-test.org:user:alice",
            None,
            b"hello self (via bob)",
        )
        .await
        .unwrap();

    // let bob receive the message
    let tsp_definitions::ReceivedTspMessage::ForwardRequest {
        opaque_payload,
        sender,
        next_hop,
        route,
    } = bobs_messages.recv().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a forward request")
    };

    assert_eq!(sender.identifier(), "did:web:did.tsp-test.org:user:alice");
    assert_eq!(next_hop.identifier(), "did:web:did.tsp-test.org:user:alice");
    assert_eq!(route, vec![b"did:web:hidden.web:user:realbob"]);

    // let alice listen
    let mut alice_messages = alice_db
        .receive("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    // bob is going to forward to alice three times; once using an incorrect intermediary, once with a correct, and once without
    bob_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:alice",
            Some("did:web:did.tsp-test.org:user:bob"),
        )
        .unwrap();

    // test1: alice doens't know "realbob"
    //TODO: the lifetime vs. Vec thing in 'Payload' vs 'ReceivedTspMessage' bites us here
    bob_db
        .forward_routed_message(
            "did:web:did.tsp-test.org:user:alice",
            route.iter().map(|x| x.as_ref()).collect(),
            &opaque_payload,
        )
        .await
        .unwrap();

    let crate::Error::UnverifiedVid(hop) = alice_messages.recv().await.unwrap().unwrap_err() else {
        panic!("alice accepted a message which she cannot handle");
    };
    assert_eq!(hop, "did:web:hidden.web:user:realbob");

    // test2: just use "bob"
    bob_db
        .forward_routed_message(
            "did:web:did.tsp-test.org:user:alice",
            vec![b"did:web:did.tsp-test.org:user:bob"],
            &opaque_payload,
        )
        .await
        .unwrap();
    let tsp_definitions::ReceivedTspMessage::ForwardRequest {
        sender,
        next_hop,
        route,
        ..
    } = alice_messages.recv().await.unwrap().unwrap()
    else {
        panic!("alice did not receive message");
    };
    assert_eq!(sender.identifier(), "did:web:did.tsp-test.org:user:bob");
    assert_eq!(next_hop.identifier(), "did:web:did.tsp-test.org:user:bob");
    assert!(route.is_empty());

    // test3: alice is the recipient (using "bob" as the 'final hop')
    bob_db
        .set_relation_for_vid(
            "did:web:did.tsp-test.org:user:bob",
            Some("did:web:did.tsp-test.org:user:alice"),
        )
        .unwrap();
    bob_db
        .forward_routed_message("did:web:did.tsp-test.org:user:bob", vec![], &opaque_payload)
        .await
        .unwrap();
    let tsp_definitions::ReceivedTspMessage::GenericMessage {
        sender, message, ..
    } = alice_messages.recv().await.unwrap().unwrap()
    else {
        panic!("alice did not receive message");
    };

    assert_eq!(sender.identifier(), "did:web:did.tsp-test.org:user:alice");
    assert_eq!(message, b"hello self (via bob)");
}

async fn faulty_send(
    sender: &impl tsp_definitions::Sender,
    receiver: &impl tsp_definitions::VerifiedVid,
    nonconfidential_data: Option<&[u8]>,
    message: &[u8],
    corrupt: impl FnOnce(&mut [u8]),
) -> Result<(), super::Error> {
    let mut tsp_message = tsp_crypto::seal(
        sender,
        receiver,
        nonconfidential_data,
        super::Payload::Content(message),
    )?;
    corrupt(&mut tsp_message);
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    Ok(())
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn attack_failures() {
    tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
        .await
        .unwrap();

    // bob database
    let mut bob_db = AsyncStore::new();
    bob_db
        .add_private_vid_from_file("test/bob.json")
        .await
        .unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    let alice = tsp_vid::PrivateVid::from_file("../examples/test/alice.json")
        .await
        .unwrap();

    let bob = tsp_vid::verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    let payload = b"hello world";

    let mut stop = false;
    for i in 0.. {
        faulty_send(&alice, &bob, None, payload, |data| {
            if i >= data.len() {
                stop = true
            } else {
                data[i] ^= 0x10
            }
        })
        .await
        .unwrap();

        assert!(bobs_messages.recv().await.unwrap().is_err());

        if stop {
            break;
        }
    }
}

#[tokio::test]
#[serial_test::serial(tcp)]
async fn test_relation_forming() {
    tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
        .await
        .unwrap();

    // bob database
    let mut bob_db = AsyncStore::new();
    bob_db
        .add_private_vid_from_file("test/bob.json")
        .await
        .unwrap();
    bob_db
        .verify_vid("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    let mut bobs_messages = bob_db
        .receive("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // alice database
    let mut alice_db = AsyncStore::new();
    alice_db
        .add_private_vid_from_file("test/alice.json")
        .await
        .unwrap();
    alice_db
        .verify_vid("did:web:did.tsp-test.org:user:bob")
        .await
        .unwrap();

    // send a message
    alice_db
        .send_relationship_request(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:bob",
        )
        .await
        .unwrap();

    // receive a message
    let tsp_definitions::ReceivedTspMessage::RequestRelationship { sender, thread_id } =
        bobs_messages.recv().await.unwrap().unwrap()
    else {
        panic!("bob did not receive a relation request")
    };

    // let alice listen
    let mut alice_messages = alice_db
        .receive("did:web:did.tsp-test.org:user:alice")
        .await
        .unwrap();

    use tsp_definitions::VerifiedVid;
    assert_eq!(sender.identifier(), "did:web:did.tsp-test.org:user:alice");

    // send the reply
    bob_db
        .send_relationship_accept(
            "did:web:did.tsp-test.org:user:bob",
            "did:web:did.tsp-test.org:user:alice",
            thread_id,
        )
        .await
        .unwrap();

    let tsp_definitions::ReceivedTspMessage::AcceptRelationship { sender } =
        alice_messages.recv().await.unwrap().unwrap()
    else {
        panic!("alice did not receive a relation accept")
    };

    assert_eq!(sender.identifier(), "did:web:did.tsp-test.org:user:bob");
}
