use std::collections::VecDeque;

pub struct ByteRing {
    data: Vec<u8>,
    capacity: usize,
    write_pos: usize,
    len: usize,
    total_written: u64,
}

impl ByteRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            capacity,
            write_pos: 0,
            len: 0,
            total_written: 0,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        self.total_written += bytes.len() as u64;

        if bytes.len() >= self.capacity {
            let start = bytes.len() - self.capacity;
            self.data.copy_from_slice(&bytes[start..]);
            self.write_pos = 0;
            self.len = self.capacity;
            return;
        }

        let first_chunk = (self.capacity - self.write_pos).min(bytes.len());
        self.data[self.write_pos..self.write_pos + first_chunk]
            .copy_from_slice(&bytes[..first_chunk]);

        if first_chunk < bytes.len() {
            let remaining = bytes.len() - first_chunk;
            self.data[..remaining].copy_from_slice(&bytes[first_chunk..]);
        }

        self.write_pos = (self.write_pos + bytes.len()) % self.capacity;
        self.len = (self.len + bytes.len()).min(self.capacity);
    }

    pub fn contents(&self) -> Vec<u8> {
        if self.len == 0 {
            return Vec::new();
        }

        let mut result = Vec::with_capacity(self.len);

        if self.len < self.capacity {
            let start = if self.write_pos >= self.len {
                self.write_pos - self.len
            } else {
                self.capacity - (self.len - self.write_pos)
            };
            if start + self.len <= self.capacity {
                result.extend_from_slice(&self.data[start..start + self.len]);
            } else {
                let first = self.capacity - start;
                result.extend_from_slice(&self.data[start..]);
                result.extend_from_slice(&self.data[..self.len - first]);
            }
        } else {
            result.extend_from_slice(&self.data[self.write_pos..]);
            result.extend_from_slice(&self.data[..self.write_pos]);
        }

        result
    }

    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct EventRing<T> {
    events: VecDeque<T>,
    capacity: usize,
}

impl<T> EventRing<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, event: T) {
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn drain_all(&mut self) -> Vec<T> {
        self.events.drain(..).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.events.iter()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_ring_basic() {
        let mut ring = ByteRing::new(10);
        ring.write(b"hello");
        assert_eq!(ring.contents(), b"hello");
        assert_eq!(ring.total_written(), 5);
    }

    #[test]
    fn byte_ring_wrap() {
        let mut ring = ByteRing::new(10);
        ring.write(b"12345678");
        ring.write(b"abcd");
        let contents = ring.contents();
        assert_eq!(std::str::from_utf8(&contents).unwrap(), "345678abcd");
    }

    #[test]
    fn byte_ring_overflow() {
        let mut ring = ByteRing::new(4);
        ring.write(b"abcdefghij");
        assert_eq!(ring.contents(), b"ghij");
    }

    #[test]
    fn event_ring_basic() {
        let mut ring = EventRing::new(3);
        ring.push(1);
        ring.push(2);
        ring.push(3);
        ring.push(4);
        let events = ring.drain_all();
        assert_eq!(events, vec![2, 3, 4]);
    }
}
