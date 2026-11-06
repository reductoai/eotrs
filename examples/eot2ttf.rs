//! eot2ttf <rtf-hex-or-eot> <out-prefix>: decodes every face to <out-prefix>N.ttf.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).expect("read");
    let bytes = if bytes
        .iter()
        .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
    {
        let hex: Vec<u8> = bytes.into_iter().filter(u8::is_ascii_hexdigit).collect();
        hex.chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    } else {
        bytes
    };
    for (i, face) in eotrs::faces(&bytes).iter().enumerate() {
        println!(
            "face {i}: bold {} italic {} {} bytes",
            face.bold,
            face.italic,
            face.data.len()
        );
        std::fs::write(format!("{}{i}.ttf", args[2]), &face.data).expect("write");
    }
}
