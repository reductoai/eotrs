fn lcg(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed >> 33
}

#[test]
fn random_input_never_panics() {
    let mut seed = 7;
    for _ in 0..20_000 {
        let len = (lcg(&mut seed) % 400) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| lcg(&mut seed) as u8).collect();
        let _ = eotrs::mtx(&b);
        if b.len() >= 82 {
            let total = b.len() as u32;
            b[0..4].copy_from_slice(&total.to_le_bytes());
            b[4..8].copy_from_slice(&(total - 82).to_le_bytes());
            b[12..16].copy_from_slice(&4u32.to_le_bytes());
        }
        let _ = eotrs::faces(&b);
    }
}
