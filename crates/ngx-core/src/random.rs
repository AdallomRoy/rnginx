//! ngx_random(): random(3) of glibc (the additive feedback generator of
//! TYPE_3: x[i] = x[i-3] + x[i-31]), with its initial state, the one
//! srandom(1) makes, so that the sequence is the one C nginx gets.

use std::cell::RefCell;

const DEG: usize = 31;
const SEP: usize = 3;

struct State {
    r: [u32; DEG],
    f: usize,
    b: usize,
}

impl State {
    /// srandom_r()
    fn seeded(seed: u32) -> State {
        let mut r = [0u32; DEG];
        let mut word: i64 = if seed == 0 { 1 } else { seed as i64 };

        r[0] = word as u32;

        for x in r.iter_mut().skip(1) {
            // word = (16807 * word) % 2147483647, without overflowing 31 bits
            let hi = word / 127773;
            let lo = word % 127773;
            word = 16807 * lo - 2836 * hi;
            if word < 0 {
                word += 2147483647;
            }
            *x = word as u32;
        }

        let mut s = State { r, f: SEP, b: 0 };

        for _ in 0..DEG * 10 {
            s.next();
        }

        s
    }

    /// random_r()
    fn next(&mut self) -> u32 {
        let val = self.r[self.f].wrapping_add(self.r[self.b]);
        self.r[self.f] = val;

        self.f += 1;
        self.b += 1;

        if self.f >= DEG {
            self.f = 0;
        } else if self.b >= DEG {
            self.b = 0;
        }

        val >> 1
    }
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::seeded(1));
}

/// random(): 0 .. 2^31 - 1
pub fn random() -> u32 {
    STATE.with(|s| s.borrow_mut().next())
}

/// srandom()
pub fn srandom(seed: u32) {
    STATE.with(|s| *s.borrow_mut() = State::seeded(seed));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_sequence() {
        // the first values of random() of glibc without srandom()
        let mut s = State::seeded(1);
        let first: Vec<u32> = (0..10).map(|_| s.next()).collect();
        assert_eq!(first, vec![1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492, 596516649, 1189641421]);

        // srandom(0) is srandom(1)
        let mut z = State::seeded(0);
        assert_eq!(z.next(), 1804289383);
    }
}
