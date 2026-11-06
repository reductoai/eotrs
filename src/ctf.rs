// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Ported from libeot (https://github.com/umanwizard/libeot).

//! CTF (compact TrueType) back to sfnt tables (port of libeot's parseCTF).

use crate::rd::Rd;

/// (bytes, x bits, y bits, x delta, y delta, x sign, y sign) per MTX triplet flag.
#[rustfmt::skip]
const TRIPLETS: [(u8, u8, u8, i32, i32, i32, i32); 128] = [
    (2, 0, 8, 0, 0, 0, -1),
    (2, 0, 8, 0, 0, 0, 1),
    (2, 0, 8, 0, 256, 0, -1),
    (2, 0, 8, 0, 256, 0, 1),
    (2, 0, 8, 0, 512, 0, -1),
    (2, 0, 8, 0, 512, 0, 1),
    (2, 0, 8, 0, 768, 0, -1),
    (2, 0, 8, 0, 768, 0, 1),
    (2, 0, 8, 0, 1024, 0, -1),
    (2, 0, 8, 0, 1024, 0, 1),
    (2, 8, 0, 0, 0, -1, 0),
    (2, 8, 0, 0, 0, 1, 0),
    (2, 8, 0, 256, 0, -1, 0),
    (2, 8, 0, 256, 0, 1, 0),
    (2, 8, 0, 512, 0, -1, 0),
    (2, 8, 0, 512, 0, 1, 0),
    (2, 8, 0, 768, 0, -1, 0),
    (2, 8, 0, 768, 0, 1, 0),
    (2, 8, 0, 1024, 0, -1, 0),
    (2, 8, 0, 1024, 0, 1, 0),
    (2, 4, 4, 1, 1, -1, -1),
    (2, 4, 4, 1, 1, 1, -1),
    (2, 4, 4, 1, 1, -1, 1),
    (2, 4, 4, 1, 1, 1, 1),
    (2, 4, 4, 1, 17, -1, -1),
    (2, 4, 4, 1, 17, 1, -1),
    (2, 4, 4, 1, 17, -1, 1),
    (2, 4, 4, 1, 17, 1, 1),
    (2, 4, 4, 1, 33, -1, -1),
    (2, 4, 4, 1, 33, 1, -1),
    (2, 4, 4, 1, 33, -1, 1),
    (2, 4, 4, 1, 33, 1, 1),
    (2, 4, 4, 1, 49, -1, -1),
    (2, 4, 4, 1, 49, 1, -1),
    (2, 4, 4, 1, 49, -1, 1),
    (2, 4, 4, 1, 49, 1, 1),
    (2, 4, 4, 17, 1, -1, -1),
    (2, 4, 4, 17, 1, 1, -1),
    (2, 4, 4, 17, 1, -1, 1),
    (2, 4, 4, 17, 1, 1, 1),
    (2, 4, 4, 17, 17, -1, -1),
    (2, 4, 4, 17, 17, 1, -1),
    (2, 4, 4, 17, 17, -1, 1),
    (2, 4, 4, 17, 17, 1, 1),
    (2, 4, 4, 17, 33, -1, -1),
    (2, 4, 4, 17, 33, 1, -1),
    (2, 4, 4, 17, 33, -1, 1),
    (2, 4, 4, 17, 33, 1, 1),
    (2, 4, 4, 17, 49, -1, -1),
    (2, 4, 4, 17, 49, 1, -1),
    (2, 4, 4, 17, 49, -1, 1),
    (2, 4, 4, 17, 49, 1, 1),
    (2, 4, 4, 33, 1, -1, -1),
    (2, 4, 4, 33, 1, 1, -1),
    (2, 4, 4, 33, 1, -1, 1),
    (2, 4, 4, 33, 1, 1, 1),
    (2, 4, 4, 33, 17, -1, -1),
    (2, 4, 4, 33, 17, 1, -1),
    (2, 4, 4, 33, 17, -1, 1),
    (2, 4, 4, 33, 17, 1, 1),
    (2, 4, 4, 33, 33, -1, -1),
    (2, 4, 4, 33, 33, 1, -1),
    (2, 4, 4, 33, 33, -1, 1),
    (2, 4, 4, 33, 33, 1, 1),
    (2, 4, 4, 33, 49, -1, -1),
    (2, 4, 4, 33, 49, 1, -1),
    (2, 4, 4, 33, 49, -1, 1),
    (2, 4, 4, 33, 49, 1, 1),
    (2, 4, 4, 49, 1, -1, -1),
    (2, 4, 4, 49, 1, 1, -1),
    (2, 4, 4, 49, 1, -1, 1),
    (2, 4, 4, 49, 1, 1, 1),
    (2, 4, 4, 49, 17, -1, -1),
    (2, 4, 4, 49, 17, 1, -1),
    (2, 4, 4, 49, 17, -1, 1),
    (2, 4, 4, 49, 17, 1, 1),
    (2, 4, 4, 49, 33, -1, -1),
    (2, 4, 4, 49, 33, 1, -1),
    (2, 4, 4, 49, 33, -1, 1),
    (2, 4, 4, 49, 33, 1, 1),
    (2, 4, 4, 49, 49, -1, -1),
    (2, 4, 4, 49, 49, 1, -1),
    (2, 4, 4, 49, 49, -1, 1),
    (2, 4, 4, 49, 49, 1, 1),
    (3, 8, 8, 1, 1, -1, -1),
    (3, 8, 8, 1, 1, 1, -1),
    (3, 8, 8, 1, 1, -1, 1),
    (3, 8, 8, 1, 1, 1, 1),
    (3, 8, 8, 1, 257, -1, -1),
    (3, 8, 8, 1, 257, 1, -1),
    (3, 8, 8, 1, 257, -1, 1),
    (3, 8, 8, 1, 257, 1, 1),
    (3, 8, 8, 1, 513, -1, -1),
    (3, 8, 8, 1, 513, 1, -1),
    (3, 8, 8, 1, 513, -1, 1),
    (3, 8, 8, 1, 513, 1, 1),
    (3, 8, 8, 257, 1, -1, -1),
    (3, 8, 8, 257, 1, 1, -1),
    (3, 8, 8, 257, 1, -1, 1),
    (3, 8, 8, 257, 1, 1, 1),
    (3, 8, 8, 257, 257, -1, -1),
    (3, 8, 8, 257, 257, 1, -1),
    (3, 8, 8, 257, 257, -1, 1),
    (3, 8, 8, 257, 257, 1, 1),
    (3, 8, 8, 257, 513, -1, -1),
    (3, 8, 8, 257, 513, 1, -1),
    (3, 8, 8, 257, 513, -1, 1),
    (3, 8, 8, 257, 513, 1, 1),
    (3, 8, 8, 513, 1, -1, -1),
    (3, 8, 8, 513, 1, 1, -1),
    (3, 8, 8, 513, 1, -1, 1),
    (3, 8, 8, 513, 1, 1, 1),
    (3, 8, 8, 513, 257, -1, -1),
    (3, 8, 8, 513, 257, 1, -1),
    (3, 8, 8, 513, 257, -1, 1),
    (3, 8, 8, 513, 257, 1, 1),
    (3, 8, 8, 513, 513, -1, -1),
    (3, 8, 8, 513, 513, 1, -1),
    (3, 8, 8, 513, 513, -1, 1),
    (3, 8, 8, 513, 513, 1, 1),
    (4, 12, 12, 0, 0, -1, -1),
    (4, 12, 12, 0, 0, 1, -1),
    (4, 12, 12, 0, 0, -1, 1),
    (4, 12, 12, 0, 0, 1, 1),
    (5, 16, 16, 0, 0, -1, -1),
    (5, 16, 16, 0, 0, 1, -1),
    (5, 16, 16, 0, 0, -1, 1),
    (5, 16, 16, 0, 0, 1, 1),
];

fn put16(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&(v as u16).to_be_bytes());
}

fn read_255_ushort(r: &mut Rd<'_>) -> Option<u16> {
    Some(match r.u8()? {
        253 => r.u16()?,
        255 => 253 + u16::from(r.u8()?),
        254 => 506 + u16::from(r.u8()?),
        c => u16::from(c),
    })
}

fn read_255_short(r: &mut Rd<'_>) -> Option<i32> {
    let mut code = r.u8()?;
    if code == 253 {
        return Some(i32::from(r.i16()?));
    }
    let sign = if code == 250 {
        code = r.u8()?;
        -1
    } else {
        1
    };
    let v = match code {
        255 => 250 + i32::from(r.u8()?),
        254 => 500 + i32::from(r.u8()?),
        c => i32::from(c),
    };
    Some(sign * v)
}

/// Groups pushed values into PUSHB/PUSHW/NPUSHB/NPUSHW runs.
#[derive(Default)]
struct Pushes {
    values: Vec<i32>,
    run: usize,
    words: bool,
}

impl Pushes {
    fn dump(&self, out: &mut Vec<u8>) {
        let n = self.run;
        if n == 0 {
            return;
        }
        if n < 8 {
            out.push(if self.words { 0xB8 } else { 0xB0 } | (n as u8 - 1));
        } else {
            out.push(if self.words { 0x41 } else { 0x40 });
            out.push(n as u8);
        }
        for &v in &self.values[self.values.len() - n..] {
            if self.words {
                put16(out, v);
            } else {
                out.push(v as u8);
            }
        }
    }

    fn put(&mut self, v: i32, out: &mut Vec<u8>) {
        let words = !(0..256).contains(&v);
        if words != self.words || self.run == 255 {
            self.dump(out);
            self.words = words;
            self.run = 0;
        }
        self.values.push(v);
        self.run += 1;
    }

    fn back2(&self) -> Option<i32> {
        self.values.len().checked_sub(2).map(|i| self.values[i])
    }
}

fn push_instructions(push: &mut Rd<'_>, out: &mut Vec<u8>, count: u16) -> Option<()> {
    let mut left = usize::from(count);
    let mut p = Pushes::default();
    while left > 0 {
        let hops = match push.peek()? {
            0xFB => 1,
            0xFC => 2,
            _ => 0,
        };
        if hops == 0 {
            let v = read_255_short(push)?;
            p.put(v, out);
            left -= 1;
            continue;
        }
        left = left.checked_sub(1 + 2 * hops)?;
        let prev = p.back2()?;
        push.u8()?;
        p.put(prev, out);
        for _ in 0..hops {
            let v = read_255_short(push)?;
            p.put(v, out);
            p.put(prev, out);
        }
    }
    p.dump(out);
    Some(())
}

pub struct Streams<'a> {
    pub glyphs: Rd<'a>,
    pub push: Rd<'a>,
    pub code: Rd<'a>,
}

fn patch16(out: &mut [u8], at: usize, v: i32) {
    out[at..at + 2].copy_from_slice(&(v as u16).to_be_bytes());
}

impl Streams<'_> {
    /// Push data, then the rest of the code; returns the instruction length.
    fn instructions(&mut self, out: &mut Vec<u8>) -> Option<usize> {
        let start = out.len();
        let pushes = read_255_ushort(&mut self.glyphs)?;
        push_instructions(&mut self.push, out, pushes)?;
        let size = read_255_ushort(&mut self.glyphs)?;
        out.extend_from_slice(self.code.take(usize::from(size))?);
        Some(out.len() - start)
    }

    fn glyph(&mut self, out: &mut Vec<u8>) -> Option<()> {
        let n = self.glyphs.i16()?;
        if n < 0 {
            return self.composite(out);
        }
        if n == 0x7FFF {
            let n = self.glyphs.i16()?;
            let mut bbox = [0i32; 4];
            for v in &mut bbox {
                *v = i32::from(self.glyphs.i16()?);
            }
            return self.simple(out, n, Some(bbox));
        }
        self.simple(out, n, None)
    }

    fn simple(&mut self, out: &mut Vec<u8>, contours: i16, bbox: Option<[i32; 4]>) -> Option<()> {
        if contours == 0 {
            return Some(());
        }
        put16(out, i32::from(contours));
        let bbox_at = out.len();
        out.extend_from_slice(&[0; 8]);
        let mut total = 1usize;
        for _ in 0..contours {
            total += usize::from(read_255_ushort(&mut self.glyphs)?);
            put16(out, total as i32 - 1);
        }
        let flags = self.glyphs.take(total)?.to_vec();
        let (xs, ys, found) = self.coordinates(&flags)?;
        let size_at = out.len();
        out.extend_from_slice(&[0; 2]);
        let size = self.instructions(out)?;
        patch16(out, size_at, size as i32);
        for (i, &f) in flags.iter().enumerate() {
            out.push(point_flags(xs[i], ys[i], f & 0x80 == 0, i == 0));
        }
        for vs in [&xs, &ys] {
            for (i, &v) in vs.iter().enumerate() {
                if i == 0 || v != 0 {
                    if (-255..256).contains(&v) {
                        out.push(v.unsigned_abs() as u8);
                    } else {
                        put16(out, v);
                    }
                }
            }
        }
        for (k, v) in bbox.unwrap_or(found).iter().enumerate() {
            patch16(out, bbox_at + 2 * k, *v);
        }
        Some(())
    }

    fn coordinates(&mut self, flags: &[u8]) -> Option<(Vec<i32>, Vec<i32>, [i32; 4])> {
        let mut xs = Vec::with_capacity(flags.len());
        let mut ys = Vec::with_capacity(flags.len());
        let (mut x, mut y) = (0i16, 0i16);
        let (lo, hi) = (i32::from(i16::MIN), i32::from(i16::MAX));
        let mut bbox = [hi, hi, lo, lo];
        for &f in flags {
            let (bytes, xb, yb, dx, dy, sx, sy) = TRIPLETS[usize::from(f & 0x7F)];
            let raw = self.glyphs.take(usize::from(bytes) - 1)?;
            let acc = raw.iter().fold(0u32, |a, &b| (a << 8) | u32::from(b));
            let total = 8 * raw.len() as u32;
            let vx = (acc >> (total - u32::from(xb))) & mask(xb);
            let vy = (acc >> (total - u32::from(xb) - u32::from(yb))) & mask(yb);
            let px = (sx * (vx as i32 + dx)) as i16;
            let py = (sy * (vy as i32 + dy)) as i16;
            xs.push(i32::from(px));
            ys.push(i32::from(py));
            x = x.wrapping_add(px);
            y = y.wrapping_add(py);
            let (cx, cy) = (i32::from(x), i32::from(y));
            bbox = [
                bbox[0].min(cx),
                bbox[1].min(cy),
                bbox[2].max(cx),
                bbox[3].max(cy),
            ];
        }
        Some((xs, ys, bbox))
    }

    fn composite(&mut self, out: &mut Vec<u8>) -> Option<()> {
        put16(out, -1);
        out.extend_from_slice(self.glyphs.take(8)?);
        loop {
            let flags = self.glyphs.u16()?;
            put16(out, i32::from(flags));
            let args = if flags & 1 != 0 { 4 } else { 2 };
            let transform = if flags & 0x80 != 0 {
                8
            } else if flags & 0x40 != 0 {
                4
            } else if flags & 0x8 != 0 {
                2
            } else {
                0
            };
            out.extend_from_slice(self.glyphs.take(2 + args + transform)?);
            if flags & 0x20 != 0 {
                continue;
            }
            if flags & 0x100 != 0 {
                let at = out.len();
                out.extend_from_slice(&[0; 2]);
                let size = self.instructions(out)?;
                patch16(out, at, size as i32);
            }
            return Some(());
        }
    }
}

fn mask(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX >> (32 - u32::from(bits))
    }
}

fn point_flags(x: i32, y: i32, on_curve: bool, first: bool) -> u8 {
    let axis = |v: i32, short: u8, same: u8| -> u8 {
        if !first && v == 0 {
            same
        } else if (-255..0).contains(&v) {
            short
        } else if (0..256).contains(&v) {
            short | same
        } else {
            0
        }
    };
    u8::from(on_curve) | axis(x, 0x02, 0x10) | axis(y, 0x04, 0x20)
}

fn loca_entry(loca: &mut Vec<u8>, at: usize, long: bool) {
    if long {
        loca.extend_from_slice(&(at as u32).to_be_bytes());
    } else {
        loca.extend_from_slice(&((at / 2) as u16).to_be_bytes());
    }
}

/// glyf and loca from the three CTF streams.
pub fn glyf_loca(s: &mut Streams<'_>, glyphs: u16, long: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut glyf = Vec::new();
    let mut loca = Vec::new();
    loca_entry(&mut loca, 0, long);
    for _ in 0..glyphs {
        s.glyph(&mut glyf)?;
        if glyf.len() % 2 == 1 {
            glyf.push(0);
        }
        loca_entry(&mut loca, glyf.len(), long);
    }
    Some((glyf, loca))
}

/// The cvt table from its CTF delta encoding.
pub fn cvt(r: &mut Rd<'_>) -> Option<Vec<u8>> {
    let n = r.u16()?;
    let mut out = Vec::with_capacity(usize::from(n) * 2);
    let mut last = 0i16;
    for _ in 0..n {
        let code = r.u8()?;
        let v: i32 = match code {
            248.. => 238 * (i32::from(code) - 247) + i32::from(r.u8()?),
            239.. => -(238 * (i32::from(code) - 239) + i32::from(r.u8()?)),
            238 => i32::from(r.i16()?),
            _ => i32::from(code),
        };
        last = last.wrapping_add(v as i16);
        out.extend_from_slice(&last.to_be_bytes());
    }
    Some(out)
}
