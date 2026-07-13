//! Lossless, out-of-order-aware TCP stream reassembly.
//!
//! Forked from `pcapzip::reassembly::StreamReassembler` rather than reused: pcapzip's version
//! treats any segment that doesn't land exactly at the next-expected byte as `Skipped`, and
//! skipped bytes are never stored anywhere -- acceptable there because pcapzip leaves the
//! original ciphertext untouched in an otherwise-preserved pcap when it skips a record. tlscap
//! has no such fallback: a skipped segment's plaintext is gone from the decoded output entirely.
//! This module buffers out-of-order segments in `pending` and drains them into `contiguous` as
//! gaps close, so reordering (e.g. from Linux's "any" cooked-capture pseudo-interface delivering
//! packets to userspace out of per-flow wire order under load) never causes silent data loss.

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;

/// One still-unconsumed slice of reassembled bytes, tagged with where it came from in the
/// original capture (packet index + byte range within that packet), mirroring
/// `pcapzip::reassembly::SourcePiece`'s bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePiece {
    pub packet_index: usize,
    pub range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    packet_index: usize,
    range: Range<usize>,
    data: Vec<u8>,
}

/// The result of pushing one packet's TCP payload into a `StreamReassembler`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Bytes landed exactly at the next-expected sequence number (or their non-overlapping tail
    /// did, after trimming a partial-overlap retransmit) and were appended to `contiguous`.
    Delivered,
    /// The entire segment was already-delivered bytes (a full retransmit) -- correctly discarded,
    /// nothing lost.
    DuplicateDiscarded,
    /// The segment (or its trimmed tail) starts after the next-expected byte -- a genuine gap.
    /// Buffered in `pending`; will drain into `contiguous` once the gap closes.
    BufferedOutOfOrder,
    /// `pending` exceeded `max_pending_bytes`; the oldest pending segment(s) were evicted to make
    /// room. This is the one case where bytes are genuinely, unrecoverably lost -- always
    /// reported, never silent. Typically means the segment that would have closed this gap was
    /// never captured at all (real upstream packet loss), which no reassembler can recover from.
    GapAbandoned { bytes: usize },
}

/// Reassembles one direction of a TCP stream. Construct one instance per (connection, direction).
pub struct StreamReassembler {
    base_seq: Option<u32>,
    next_expected_relative: u64,
    contiguous: VecDeque<Segment>,
    contiguous_len: usize,
    pending: BTreeMap<u64, Segment>,
    pending_len: usize,
    max_pending_bytes: usize,
}

/// A default cap on out-of-order-buffered bytes per direction. Generous relative to a single TLS
/// record (max 16KB + 5-byte header), sized to tolerate several records' worth of reordering
/// before treating a gap as abandoned.
pub const DEFAULT_MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

impl StreamReassembler {
    pub fn new() -> Self {
        Self::with_max_pending_bytes(DEFAULT_MAX_PENDING_BYTES)
    }

    pub fn with_max_pending_bytes(max_pending_bytes: usize) -> Self {
        Self {
            base_seq: None,
            next_expected_relative: 0,
            contiguous: VecDeque::new(),
            contiguous_len: 0,
            pending: BTreeMap::new(),
            pending_len: 0,
            max_pending_bytes,
        }
    }

    /// Anchors this reassembler's sequence-number arithmetic to a stream's true starting
    /// sequence number (i.e. the SYN packet's `seq`, which is one less than the first data
    /// byte's sequence number -- callers should pass `syn_seq.wrapping_add(1)`). Must be called
    /// before the first `push()`, if the SYN was actually observed, so that a segment arriving
    /// out of order *relative to the true stream start* (not just relative to whatever happened
    /// to be pushed first) is correctly recognized as out-of-order rather than mis-anchoring the
    /// whole stream to itself. A no-op if a base is already set (idempotent, first call wins).
    pub fn set_isn(&mut self, first_byte_seq: u32) {
        if self.base_seq.is_none() {
            self.base_seq = Some(first_byte_seq);
        }
    }

    fn relative_seq(&mut self, seq: u32) -> u64 {
        // Fallback for when the SYN was never observed (e.g. capture started mid-connection):
        // best-effort, anchors to whatever arrives first. No reassembler can do better without
        // ground truth for the stream's true start in that case.
        let base = *self.base_seq.get_or_insert(seq);
        seq.wrapping_sub(base) as u64
    }

    /// Feed one packet's TCP payload in. `packet_index` and `range` identify where these bytes
    /// live in the original capture, for downstream provenance tracking; `seq` is the packet's
    /// TCP sequence number; `payload` is the actual bytes.
    pub fn push(
        &mut self,
        packet_index: usize,
        seq: u32,
        range: Range<usize>,
        payload: &[u8],
    ) -> PushOutcome {
        if payload.is_empty() {
            return PushOutcome::DuplicateDiscarded;
        }
        let rel = self.relative_seq(seq);
        self.push_relative(packet_index, range, payload, rel)
    }

    fn push_relative(
        &mut self,
        packet_index: usize,
        range: Range<usize>,
        payload: &[u8],
        rel: u64,
    ) -> PushOutcome {
        let rel_end = rel + payload.len() as u64;

        // Case 1: fully-delivered-already retransmit. Nothing new here.
        if rel_end <= self.next_expected_relative {
            return PushOutcome::DuplicateDiscarded;
        }

        // Case 2: partial overlap -- trim the already-delivered prefix, keep only the new tail.
        // Never silently drop the new part along with the duplicate part.
        let (rel, range, payload_owned): (u64, Range<usize>, Vec<u8>) =
            if rel < self.next_expected_relative {
                let trim = (self.next_expected_relative - rel) as usize;
                (
                    self.next_expected_relative,
                    (range.start + trim)..range.end,
                    payload[trim..].to_vec(),
                )
            } else {
                (rel, range, payload.to_vec())
            };

        if rel == self.next_expected_relative {
            // Case 3: exact next byte -- deliver directly, then drain any now-contiguous pending segments.
            self.deliver(Segment {
                packet_index,
                range,
                data: payload_owned,
            });
            self.drain_pending();
            PushOutcome::Delivered
        } else {
            // Case 4: genuine gap -- buffer out of order.
            debug_assert!(rel > self.next_expected_relative);
            let seg = Segment {
                packet_index,
                range,
                data: payload_owned,
            };
            self.buffer_pending(rel, seg)
        }
    }

    fn deliver(&mut self, seg: Segment) {
        self.next_expected_relative += seg.data.len() as u64;
        self.contiguous_len += seg.data.len();
        self.contiguous.push_back(seg);
    }

    fn drain_pending(&mut self) {
        while let Some((&key, _)) = self.pending.iter().next() {
            if key < self.next_expected_relative {
                // A pending segment can itself have become partially/fully redundant if the gap
                // was closed by a segment whose tail overlaps it -- trim/discard the same way
                // push_relative's cases 1/2 do, then re-insert or drop.
                let seg = self.pending.remove(&key).unwrap();
                self.pending_len -= seg.data.len();
                let rel_end = key + seg.data.len() as u64;
                if rel_end <= self.next_expected_relative {
                    continue; // now fully redundant, discard
                }
                let trim = (self.next_expected_relative - key) as usize;
                let trimmed = Segment {
                    packet_index: seg.packet_index,
                    range: (seg.range.start + trim)..seg.range.end,
                    data: seg.data[trim..].to_vec(),
                };
                self.deliver(trimmed);
                continue;
            }
            if key != self.next_expected_relative {
                break; // still a gap
            }
            let seg = self.pending.remove(&key).unwrap();
            self.pending_len -= seg.data.len();
            self.deliver(seg);
        }
    }

    fn buffer_pending(&mut self, rel: u64, seg: Segment) -> PushOutcome {
        // Duplicate/overlapping out-of-order segment already pending at this exact start? Keep
        // whichever is longer (or just overwrite -- both are equally valid captures of the same
        // bytes); this is not a loss case either way.
        let incoming_len = seg.data.len();
        if let Some(existing) = self.pending.get(&rel) {
            if existing.data.len() >= incoming_len {
                return PushOutcome::DuplicateDiscarded;
            }
            self.pending_len -= existing.data.len();
        }

        self.pending.insert(rel, seg);
        self.pending_len += incoming_len;

        if self.pending_len <= self.max_pending_bytes {
            return PushOutcome::BufferedOutOfOrder;
        }

        // Over budget: evict the oldest (lowest-sequence) pending segments until back under the
        // cap. These bytes are genuinely, unrecoverably lost -- report exactly how many.
        let mut evicted_bytes = 0usize;
        while self.pending_len > self.max_pending_bytes {
            let Some((&oldest_key, _)) = self.pending.iter().next() else {
                break;
            };
            let removed = self.pending.remove(&oldest_key).unwrap();
            self.pending_len -= removed.data.len();
            evicted_bytes += removed.data.len();
        }
        PushOutcome::GapAbandoned {
            bytes: evicted_bytes,
        }
    }

    /// Total bytes currently sitting in `contiguous`, ready to be consumed.
    pub fn contiguous_len(&self) -> usize {
        self.contiguous_len
    }

    /// Total bytes currently buffered out-of-order, waiting for a gap to close.
    pub fn pending_len(&self) -> usize {
        self.pending_len
    }

    /// Copies out up to `n` contiguous bytes from the front (without consuming them), along with
    /// their source provenance. Used by TLS record extraction to peek a header before deciding
    /// how much to consume.
    pub fn peek(&self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n.min(self.contiguous_len));
        for seg in &self.contiguous {
            if out.len() >= n {
                break;
            }
            let take = (n - out.len()).min(seg.data.len());
            out.extend_from_slice(&seg.data[..take]);
        }
        out
    }

    /// Consumes exactly `n` contiguous bytes from the front, returning the bytes and their
    /// per-source-packet provenance. Panics if fewer than `n` bytes are available -- callers must
    /// check `contiguous_len()` first (mirrors `pcapzip::reassembly`'s own contract).
    pub fn take_bytes(&mut self, n: usize) -> (Vec<u8>, Vec<SourcePiece>) {
        assert!(
            n <= self.contiguous_len,
            "take_bytes: not enough contiguous bytes buffered"
        );
        let mut out = Vec::with_capacity(n);
        let mut pieces = Vec::new();
        let mut remaining = n;
        while remaining > 0 {
            let seg = self
                .contiguous
                .front_mut()
                .expect("contiguous_len tracked incorrectly");
            let take = remaining.min(seg.data.len());
            out.extend_from_slice(&seg.data[..take]);
            pieces.push(SourcePiece {
                packet_index: seg.packet_index,
                range: seg.range.start..(seg.range.start + take),
            });
            if take == seg.data.len() {
                self.contiguous.pop_front();
            } else {
                seg.data.drain(..take);
                seg.range.start += take;
            }
            self.contiguous_len -= take;
            remaining -= take;
        }
        (out, pieces)
    }
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(r: &mut StreamReassembler, seq: u32, payload: &[u8]) -> PushOutcome {
        r.push(0, seq, 0..payload.len(), payload)
    }

    #[test]
    fn in_order_delivery() {
        let mut r = StreamReassembler::new();
        assert_eq!(push(&mut r, 1000, b"hello"), PushOutcome::Delivered);
        assert_eq!(push(&mut r, 1005, b"world"), PushOutcome::Delivered);
        assert_eq!(r.contiguous_len(), 10);
        let (bytes, _) = r.take_bytes(10);
        assert_eq!(bytes, b"helloworld");
    }

    #[test]
    fn two_segment_reorder_recovers_both() {
        let mut r = StreamReassembler::new();
        r.set_isn(1000);
        // "world" arrives before "hello" -- must not be lost.
        assert_eq!(
            push(&mut r, 1005, b"world"),
            PushOutcome::BufferedOutOfOrder
        );
        assert_eq!(r.contiguous_len(), 0);
        assert_eq!(r.pending_len(), 5);
        assert_eq!(push(&mut r, 1000, b"hello"), PushOutcome::Delivered);
        assert_eq!(r.contiguous_len(), 10);
        assert_eq!(r.pending_len(), 0);
        let (bytes, _) = r.take_bytes(10);
        assert_eq!(bytes, b"helloworld");
    }

    #[test]
    fn three_segment_reorder_all_orders_recover() {
        // Try all 6 arrival orders of 3 segments; all must reassemble identically.
        let segs: [(u32, &[u8]); 3] = [(1000, b"AAAAA"), (1005, b"BBBBB"), (1010, b"CCCCC")];
        let orders: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for order in orders {
            let mut r = StreamReassembler::new();
            r.set_isn(1000);
            for &idx in &order {
                let (seq, payload) = segs[idx];
                push(&mut r, seq, payload);
            }
            assert_eq!(
                r.contiguous_len(),
                15,
                "order {:?} failed to fully reassemble",
                order
            );
            let (bytes, _) = r.take_bytes(15);
            assert_eq!(
                bytes, b"AAAAABBBBBCCCCC",
                "order {:?} produced wrong bytes",
                order
            );
        }
    }

    #[test]
    fn exact_duplicate_retransmit_discarded_no_loss() {
        let mut r = StreamReassembler::new();
        assert_eq!(push(&mut r, 1000, b"hello"), PushOutcome::Delivered);
        // Full retransmit of the same bytes.
        assert_eq!(
            push(&mut r, 1000, b"hello"),
            PushOutcome::DuplicateDiscarded
        );
        assert_eq!(r.contiguous_len(), 5);
        let (bytes, _) = r.take_bytes(5);
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn partial_overlap_retransmit_keeps_new_tail() {
        let mut r = StreamReassembler::new();
        assert_eq!(push(&mut r, 1000, b"hello"), PushOutcome::Delivered);
        // Retransmit that repeats "lo" (already delivered) but also carries new " world" bytes.
        assert_eq!(push(&mut r, 1003, b"lo world"), PushOutcome::Delivered);
        assert_eq!(r.contiguous_len(), 11);
        let (bytes, _) = r.take_bytes(11);
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn multiple_simultaneous_gaps_drain_in_order() {
        let mut r = StreamReassembler::new();
        r.set_isn(1000);
        // Segments at relative 0, 5, 10, 15 -- deliver 15 first (gap), then 10 (gap), then 5 (gap),
        // then 0 (closes everything, should drain all three pending in one go).
        push(&mut r, 1015, b"DDDDD");
        push(&mut r, 1010, b"CCCCC");
        push(&mut r, 1005, b"BBBBB");
        assert_eq!(r.pending_len(), 15);
        assert_eq!(push(&mut r, 1000, b"AAAAA"), PushOutcome::Delivered);
        assert_eq!(r.pending_len(), 0);
        assert_eq!(r.contiguous_len(), 20);
        let (bytes, _) = r.take_bytes(20);
        assert_eq!(bytes, b"AAAAABBBBBCCCCCDDDDD");
    }

    #[test]
    fn gap_never_fills_triggers_abandonment_when_over_budget() {
        let mut r = StreamReassembler::with_max_pending_bytes(10);
        r.set_isn(1000);
        // First segment never arrives. Keep feeding out-of-order segments past the cap.
        assert_eq!(
            push(&mut r, 2000, &[b'x'; 6]),
            PushOutcome::BufferedOutOfOrder
        );
        assert_eq!(
            push(&mut r, 3000, &[b'y'; 6]),
            PushOutcome::GapAbandoned { bytes: 6 }
        );
        // The oldest pending entry (the first 6 'x' bytes) was evicted to make room; the newest
        // segment survives in pending.
        assert_eq!(r.pending_len(), 6);
    }

    #[test]
    fn take_bytes_spans_multiple_source_segments_with_provenance() {
        let mut r = StreamReassembler::new();
        r.push(0, 1000, 100..105, b"hello");
        r.push(1, 1005, 200..205, b"world");
        let (bytes, pieces) = r.take_bytes(10);
        assert_eq!(bytes, b"helloworld");
        assert_eq!(pieces.len(), 2);
        assert_eq!(
            pieces[0],
            SourcePiece {
                packet_index: 0,
                range: 100..105
            }
        );
        assert_eq!(
            pieces[1],
            SourcePiece {
                packet_index: 1,
                range: 200..205
            }
        );
    }

    #[test]
    fn take_bytes_partial_consumption_leaves_remainder_with_trimmed_provenance() {
        let mut r = StreamReassembler::new();
        r.push(0, 1000, 100..110, b"helloworld");
        let (bytes, pieces) = r.take_bytes(5);
        assert_eq!(bytes, b"hello");
        assert_eq!(
            pieces,
            vec![SourcePiece {
                packet_index: 0,
                range: 100..105
            }]
        );
        assert_eq!(r.contiguous_len(), 5);
        let (bytes2, pieces2) = r.take_bytes(5);
        assert_eq!(bytes2, b"world");
        assert_eq!(
            pieces2,
            vec![SourcePiece {
                packet_index: 0,
                range: 105..110
            }]
        );
    }

    #[test]
    fn empty_payload_is_noop() {
        let mut r = StreamReassembler::new();
        assert_eq!(push(&mut r, 1000, b""), PushOutcome::DuplicateDiscarded);
        assert_eq!(r.contiguous_len(), 0);
    }

    #[test]
    fn sequence_number_wraparound_handled_via_wrapping_sub() {
        let mut r = StreamReassembler::new();
        // Start near the u32 boundary and wrap: a 2-byte push at MAX-1 covers seq MAX-1, MAX;
        // the next byte's sequence number wraps around to 0.
        let near_max = u32::MAX - 1;
        assert_eq!(push(&mut r, near_max, b"AB"), PushOutcome::Delivered); // consumes seq MAX-1, MAX
        assert_eq!(push(&mut r, 0, b"CD"), PushOutcome::Delivered); // wraps to seq 0
        let (bytes, _) = r.take_bytes(4);
        assert_eq!(bytes, b"ABCD");
    }
}
