// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Ported from libeot (https://github.com/umanwizard/libeot).

//! Embedded OpenType to TrueType. MicroType Express decoding is a port of
//! libeot (Brennan T. Vincent) and Monotype's reference LZCOMP.

mod ctf;
mod lzcomp;

pub(crate) mod rd {
    pub struct Rd<'a> {
        pub data: &'a [u8],
        pub pos: usize,
    }

    impl<'a> Rd<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0 }
        }

        pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let s = self.data.get(self.pos..self.pos.checked_add(n)?)?;
            self.pos += n;
            Some(s)
        }

        pub fn peek(&self) -> Option<u8> {
            self.data.get(self.pos).copied()
        }

        pub fn u8(&mut self) -> Option<u8> {
            Some(self.take(1)?[0])
        }

        pub fn u16(&mut self) -> Option<u16> {
            Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
        }

        pub fn i16(&mut self) -> Option<i16> {
            Some(i16::from_be_bytes(self.take(2)?.try_into().ok()?))
        }

        pub fn u24(&mut self) -> Option<usize> {
            let b = self.take(3)?;
            Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
        }

        pub fn u32(&mut self) -> Option<u32> {
            Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
        }
    }
}

use rd::Rd;

/// One decoded face.
pub struct Face {
    pub bold: bool,
    pub italic: bool,
    /// A plain TrueType file.
    pub data: Vec<u8>,
}

const TTCOMPRESSED: u32 = 0x4;
const XORENCRYPT: u32 = 0x1000_0000;

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Faces of a run of EOT files laid end to end, as RTF's \\fontemb carries them.
#[must_use]
pub fn faces(blob: &[u8]) -> Vec<Face> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(size) = le32(blob, at).map(|s| s as usize) {
        if size < 32 || at + size > blob.len() {
            break;
        }
        if let Some(face) = decode(&blob[at..at + size]) {
            out.push(face);
        }
        at += size;
    }
    out
}

/// One EOT file to its face.
#[must_use]
pub fn decode(eot: &[u8]) -> Option<Face> {
    let total = le32(eot, 0)? as usize;
    let font_size = le32(eot, 4)? as usize;
    let flags = le32(eot, 12)?;
    let italic = *eot.get(27)? != 0;
    let weight = le32(eot, 28)?;
    let mut font = eot.get(total.checked_sub(font_size)?..total)?.to_vec();
    if flags & XORENCRYPT != 0 {
        for b in &mut font {
            *b ^= 0x50;
        }
    }
    let data = if flags & TTCOMPRESSED != 0 {
        mtx(&font)?
    } else {
        font
    };
    Some(Face {
        bold: weight > 500,
        italic,
        data,
    })
}

/// A MicroType Express container to a TrueType file.
#[must_use]
pub fn mtx(data: &[u8]) -> Option<Vec<u8>> {
    let mut r = Rd::new(data);
    let version = r.u8()?;
    let _copy_limit = r.u24()?;
    let (b2, b3) = (r.u24()?, r.u24()?);
    let block = |a: usize, b: usize| lzcomp::unpack(data.get(a..b)?, version);
    let glyphs = block(10, b2)?;
    let push = block(b2, b3)?;
    let code = block(b3, data.len())?;
    sfnt(&glyphs, &push, &code)
}

fn sfnt(main: &[u8], push: &[u8], code: &[u8]) -> Option<Vec<u8>> {
    let mut r = Rd::new(main);
    r.u32()?;
    let n = r.u16()?;
    r.take(6)?;
    let mut dir = Vec::new();
    for _ in 0..n {
        let tag: [u8; 4] = r.take(4)?.try_into().ok()?;
        r.u32()?;
        let (offset, len) = (r.u32()? as usize, r.u32()? as usize);
        if &tag != b"hdmx" && &tag != b"VDMX" {
            dir.push((tag, offset, len));
        }
    }
    let table = |tag: &[u8; 4]| {
        dir.iter()
            .find(|t| &t.0 == tag)
            .map(|t| main.get(t.1..t.1 + t.2))
    };
    let head = table(b"head")??;
    let maxp = table(b"maxp")??;
    table(b"hmtx")??;
    let long_loca = Rd {
        data: head,
        pos: 50,
    }
    .i16()?
        != 0;
    let glyph_count = Rd { data: maxp, pos: 4 }.u16()?;
    let mut tables: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    if let Some(&(_, offset, _)) = dir.iter().find(|t| &t.0 == b"glyf") {
        let mut s = ctf::Streams {
            glyphs: Rd {
                data: main,
                pos: offset,
            },
            push: Rd::new(push),
            code: Rd::new(code),
        };
        let (glyf, loca) = ctf::glyf_loca(&mut s, glyph_count, long_loca)?;
        tables.push((*b"glyf", glyf));
        tables.push((*b"loca", loca));
    }
    for &(tag, offset, len) in &dir {
        let body = match &tag {
            b"glyf" | b"loca" => continue,
            b"cvt " => ctf::cvt(&mut Rd {
                data: main,
                pos: offset,
            })?,
            _ => main.get(offset..offset + len)?.to_vec(),
        };
        tables.push((tag, body));
    }
    Some(assemble(tables))
}

fn checksum(b: &[u8]) -> u32 {
    b.chunks(4).fold(0u32, |s, c| {
        let mut w = [0u8; 4];
        w[..c.len()].copy_from_slice(c);
        s.wrapping_add(u32::from_be_bytes(w))
    })
}

fn assemble(mut tables: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
    tables.sort_by_key(|t| t.0);
    if let Some((_, head)) = tables.iter_mut().find(|t| &t.0 == b"head")
        && head.len() >= 12
    {
        head[8..12].fill(0);
    }
    let n = tables.len();
    let pow = if n == 0 {
        1
    } else {
        1usize << (usize::BITS - 1 - n.leading_zeros())
    };
    let mut out = Vec::new();
    out.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    for v in [
        n,
        pow * 16,
        pow.trailing_zeros() as usize,
        n * 16 - pow * 16,
    ] {
        out.extend_from_slice(&(v as u16).to_be_bytes());
    }
    let mut offset = 12 + 16 * n;
    let mut head_at = None;
    for (tag, body) in &tables {
        out.extend_from_slice(tag);
        out.extend_from_slice(&checksum(body).to_be_bytes());
        out.extend_from_slice(&(offset as u32).to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        if tag == b"head" {
            head_at = Some(offset);
        }
        offset += body.len().div_ceil(4) * 4;
    }
    for (_, body) in &tables {
        out.extend_from_slice(body);
        out.resize(out.len().div_ceil(4) * 4, 0);
    }
    if let Some(at) = head_at {
        let adjust = 0xB1B0_AFBAu32.wrapping_sub(checksum(&out));
        out[at + 8..at + 12].copy_from_slice(&adjust.to_be_bytes());
    }
    out
}
