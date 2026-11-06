// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Ported from libeot (https://github.com/umanwizard/libeot).

//! LZCOMP, the adaptive-Huffman LZ77 stage of MicroType Express (port of libeot's lzcomp).

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u8,
    left: u32,
}

impl Bits<'_> {
    fn bit(&mut self) -> Option<bool> {
        if self.left == 0 {
            self.buf = *self.data.get(self.pos)?;
            self.pos += 1;
            self.left = 8;
        }
        self.left -= 1;
        Some((self.buf >> self.left) & 1 == 1)
    }

    fn value(&mut self, n: u32) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from(self.bit()?);
        }
        Some(v)
    }
}

#[derive(Clone, Copy, Default)]
struct Node {
    up: usize,
    left: usize,
    right: usize,
    code: Option<usize>,
    weight: u64,
}

const ROOT: usize = 1;

struct Ahuff {
    tree: Vec<Node>,
    index: Vec<usize>,
}

impl Ahuff {
    fn new(range: usize) -> Self {
        let mut tree = vec![Node::default(); 2 * range];
        for (i, node) in tree.iter_mut().enumerate().skip(2) {
            node.up = i / 2;
            node.weight = 1;
        }
        for (i, node) in tree.iter_mut().enumerate().take(range).skip(1) {
            node.left = 2 * i;
            node.right = 2 * i + 1;
        }
        let mut index = vec![0; range];
        for (i, slot) in index.iter_mut().enumerate() {
            tree[range + i].code = Some(i);
            *slot = range + i;
        }
        for i in (1..range).rev() {
            tree[i].weight = tree[tree[i].left].weight + tree[tree[i].right].weight;
        }
        let mut t = Self { tree, index };
        if range > 256 && range < 512 {
            t.bump(256);
            t.bump(257);
            for _ in 0..12 {
                t.bump(range - 3);
            }
            for _ in 0..6 {
                t.bump(range - 2);
            }
        } else {
            for _ in 0..2 {
                for i in 0..range {
                    t.bump(i);
                }
            }
        }
        t
    }

    fn bump(&mut self, symbol: usize) {
        self.update(self.index[symbol]);
    }

    fn swap(&mut self, a: usize, b: usize) {
        let (upa, upb) = (self.tree[a].up, self.tree[b].up);
        self.tree.swap(a, b);
        self.tree[a].up = upa;
        self.tree[b].up = upb;
        for x in [a, b] {
            let n = self.tree[x];
            if let Some(code) = n.code {
                self.index[code] = x;
            } else {
                self.tree[n.left].up = x;
                self.tree[n.right].up = x;
            }
        }
    }

    fn update(&mut self, mut a: usize) {
        while a != ROOT {
            let w = self.tree[a].weight;
            let mut b = a - 1;
            if self.tree[b].weight == w {
                while self.tree[b].weight == w {
                    b -= 1;
                }
                b += 1;
                if b > ROOT {
                    self.swap(a, b);
                    a = b;
                }
            }
            self.tree[a].weight = w + 1;
            a = self.tree[a].up;
        }
        self.tree[ROOT].weight += 1;
    }

    fn read(&mut self, bits: &mut Bits<'_>) -> Option<usize> {
        let mut a = ROOT;
        let code = loop {
            let n = self.tree[a];
            a = if bits.bit()? { n.right } else { n.left };
            if let Some(code) = self.tree.get(a)?.code {
                break code;
            }
        };
        self.update(a);
        Some(code)
    }
}

const PRELOAD: usize = 2 * 32 * 96 + 4 * 256;

fn preload() -> Vec<u8> {
    let mut w = Vec::with_capacity(PRELOAD);
    for k in 0..32u8 {
        for j in 0..96u8 {
            w.extend([k, j]);
        }
    }
    for j in 0..=255u8 {
        w.extend([j; 4]);
    }
    w
}

#[derive(Default)]
struct RunLength {
    escape: Option<u8>,
    seen: bool,
    count: Option<u8>,
    out: Vec<u8>,
}

impl RunLength {
    fn push(&mut self, v: u8) {
        let Some(escape) = self.escape else {
            self.escape = Some(v);
            return;
        };
        if let Some(n) = self.count.take() {
            self.out.extend(std::iter::repeat_n(v, usize::from(n)));
        } else if self.seen {
            self.seen = false;
            if v == 0 {
                self.out.push(escape);
            } else {
                self.count = Some(v);
            }
        } else if v == escape {
            self.seen = true;
        } else {
            self.out.push(v);
        }
    }
}

struct Coders {
    dist: Ahuff,
    len: Ahuff,
    sym: Ahuff,
    dup: [usize; 3],
}

impl Coders {
    fn length(&mut self, bits: &mut Bits<'_>, symbol: usize) -> Option<(usize, usize)> {
        let first = symbol - 256;
        let ranges = first / 8 + 1;
        let mut b = first % 8;
        let mut value = 0;
        loop {
            let done = b & 4 == 0;
            value = (value << 2) | (b & 3);
            if done {
                break;
            }
            b = self.len.read(bits)?;
        }
        Some((value + 2, ranges))
    }

    fn distance(&mut self, bits: &mut Bits<'_>, ranges: usize) -> Option<usize> {
        let mut value = 0usize;
        for _ in 0..ranges {
            value = value.checked_shl(3)? | self.dist.read(bits)?;
        }
        Some(value + 1)
    }
}

/// One LZCOMP block back to its bytes.
pub fn unpack(data: &[u8], version: u8) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let mut bits = Bits {
        data,
        pos: 0,
        buf: 0,
        left: 0,
    };
    let run_length = version != 1 && bits.bit()?;
    let dist = Ahuff::new(8);
    let len = Ahuff::new(8);
    let out_len = bits.value(24)? as usize;
    let mut ranges = 1;
    while (1usize << (3 * ranges)) < out_len {
        ranges += 1;
    }
    let dup2 = 256 + 8 * ranges;
    let mut c = Coders {
        dist,
        len,
        sym: Ahuff::new(dup2 + 3),
        dup: [dup2, dup2 + 1, dup2 + 2],
    };
    let mut win = preload();
    win.reserve(out_len);
    let mut rl = RunLength::default();
    let mut emit = |win: &mut Vec<u8>, v: u8| {
        win.push(v);
        if run_length {
            rl.push(v)
        } else {
            rl.out.push(v)
        }
    };
    while win.len() - PRELOAD < out_len {
        let symbol = c.sym.read(&mut bits)?;
        if symbol < 256 {
            emit(&mut win, symbol as u8);
        } else if let Some(k) = c.dup.iter().position(|&d| d == symbol) {
            let v = win[win.len().checked_sub(2 * (k + 1))?];
            emit(&mut win, v);
        } else {
            let (mut length, ranges) = c.length(&mut bits, symbol)?;
            let distance = c.distance(&mut bits, ranges)?;
            if distance >= 512 {
                length += 1;
            }
            let start = (win.len() + 1).checked_sub(distance + length)?;
            for j in 0..length {
                let v = win[start + j];
                emit(&mut win, v);
            }
        }
    }
    (win.len() - PRELOAD == out_len).then_some(rl.out)
}
