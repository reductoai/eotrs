fn eot(font: &[u8], flags: u32, weight: u32, italic: bool) -> Vec<u8> {
    let mut h = vec![0u8; 82];
    let total = (h.len() + font.len()) as u32;
    h[0..4].copy_from_slice(&total.to_le_bytes());
    h[4..8].copy_from_slice(&(font.len() as u32).to_le_bytes());
    h[8..12].copy_from_slice(&0x0002_0001u32.to_le_bytes());
    h[12..16].copy_from_slice(&flags.to_le_bytes());
    h[27] = u8::from(italic);
    h[28..32].copy_from_slice(&weight.to_le_bytes());
    h.extend_from_slice(font);
    h
}

#[test]
fn splits_faces_and_undoes_xor() {
    let font = b"\x00\x01\x00\x00plain sfnt bytes";
    let xored: Vec<u8> = font.iter().map(|b| b ^ 0x50).collect();
    let mut blob = eot(font, 0, 400, false);
    blob.extend(eot(&xored, 0x1000_0000, 700, true));
    let faces = eotrs::faces(&blob);
    assert_eq!(faces.len(), 2);
    assert_eq!(faces[0].data, font);
    assert!(!faces[0].bold && !faces[0].italic);
    assert_eq!(faces[1].data, font);
    assert!(faces[1].bold && faces[1].italic);
}

#[test]
fn stops_at_a_truncated_face() {
    let mut blob = eot(b"abcd", 0, 400, false);
    blob.extend_from_slice(&[0xff; 8]);
    assert_eq!(eotrs::faces(&blob).len(), 1);
}
