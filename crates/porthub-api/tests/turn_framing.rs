#[test]
fn turn_tcp_framing_preserves_split_coalesced_and_padded_messages() {
    use porthub_api::legacy_turn::Framing;

    let mut frame = Framing::default();
    let mut stun = vec![0u8; 24];
    stun[1] = 1;
    stun[3] = 4;
    let channel = vec![0x40, 1, 0, 3, 1, 2, 3, 0];
    frame.push(&stun[..3]).unwrap();
    assert!(frame.packet().unwrap().is_none());
    frame.push(&[&stun[3..], &channel].concat()).unwrap();
    assert_eq!(frame.packet().unwrap(), Some(stun));
    assert_eq!(frame.packet().unwrap(), Some(channel));
    assert!(frame.packet().unwrap().is_none());
    frame.push(&[0x80, 0, 0, 0]).unwrap();
    assert!(frame.packet().is_err());
}
