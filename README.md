# eotrs

Embedded OpenType (`.eot`) to TrueType in pure Rust: no C, no unsafe, builds for wasm.

It reads the EOT header, removes XOR obfuscation, decompresses MicroType Express
(LZCOMP + CTF) and rebuilds a plain sfnt with fresh checksums.

```rust
let face = eotrs::decode(&eot_bytes).expect("valid EOT");
std::fs::write("font.ttf", face.data)?;

// Several EOT files laid end to end, as RTF's \fontemb carries them
for face in eotrs::faces(&blob) {
    println!("bold {} italic {}", face.bold, face.italic);
}
```

`cargo run --example eot2ttf <file.eot|hex> <out-prefix>` writes each face to `<out-prefix>N.ttf`.

## Status

Checked on 71 faces taken from Word-saved RTF (Calibri, Cambria, Inter, CJK fonts up to
19k glyphs): every glyph draws, and glyf, loca, cvt and all copied tables match the faces
Word itself writes into a .docx.

Not handled: EOT subsetting metadata beyond the header, and hdmx/VDMX (MTX drops them).

## Licence and patents

A port of [libeot](https://github.com/umanwizard/libeot) by Brennan T. Vincent,
whose LZCOMP code comes from Monotype's MTX reference and was relicensed under MPL-2.0.
This crate is MPL-2.0 too (see `LICENSE`).

EOT and MicroType Express were submitted to the W3C by Microsoft and Monotype with
patent grants (https://www.w3.org/Submission/2008/01/). Check that they cover your use.
