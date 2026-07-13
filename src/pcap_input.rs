//! Reads a pcap or pcapng byte stream (from stdin, in production -- `tcpdump -w - | tlscap ...`)
//! and yields parsed TCP frames, including the TCP flags (FIN/RST/SYN/ACK) `orchestrator.rs`
//! needs for eviction. Auto-detects classic pcap vs. pcapng via the leading magic bytes, since
//! `tcpdump`'s exact default output format across builds/versions isn't something to hardcode a
//! single assumption about.

use std::io::Read;
use std::net::IpAddr;
use std::ops::Range;
use std::time::Duration;

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use pcap_file::{DataLink, PcapError};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub ack: bool,
    /// Not consulted by reassembly/eviction (unlike the other four) -- carried through purely for
    /// `orchestrator.rs`'s packet-level output events, which surface it for connection-lifecycle
    /// visibility in Athena (e.g. distinguishing a pure ACK from a data segment).
    pub psh: bool,
}

/// One captured TCP segment, parsed down to exactly what `orchestrator.rs` needs: which
/// connection it belongs to, its sequence number and flags, and the byte range of its payload
/// within the original packet buffer (kept as a `Range` into the same buffer the caller already
/// owns, rather than a fresh copy, so `reassembly::StreamReassembler::push` can record accurate
/// provenance without an extra allocation per packet).
pub struct TcpFrame {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    /// The acknowledgment number -- not consulted by reassembly/eviction, carried through purely
    /// for `orchestrator.rs`'s packet-level output events (see `TcpFlags::psh`'s doc comment).
    pub ack_number: u32,
    pub flags: TcpFlags,
    pub payload_range: Range<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not a TCP/IP frame (or truncated below a full IP+TCP header)")]
    NotTcp,
}

/// Linux "cooked capture" v1 (SLL, used by older `tcpdump -i any`) header length: packet_type(2) +
/// arphrd_type(2) + addr_len(2) + addr(8, padded) + protocol_type(2) = 16 bytes, then directly the
/// network-layer payload (no separate ethertype-dispatch step needed -- IP starts right after).
const LINUX_SLL_HEADER_LEN: usize = 16;

/// Linux "cooked capture" v2 (SLL2, LINKTYPE_LINUX_SLL2 / 276 -- what modern `tcpdump -i any`
/// actually emits; confirmed empirically against a real production capture, whose `capinfos`
/// output showed "Linux cooked-mode capture v2" and whose first packet's hex dump matched this
/// exact 20-byte layout byte-for-byte, NOT the older 16-byte v1 layout below). Field order is
/// different from v1 too: protocol_type(2) + reserved(2) + interface_index(4) + arphrd_type(2) +
/// packet_type(1) + addr_len(1) + addr(8, padded) = 20 bytes, then the network-layer payload.
const LINUX_SLL2_HEADER_LEN: usize = 20;

/// BSD loopback (DLT_NULL/LINKTYPE_NULL, 0 -- macOS/BSD's `lo0`; DLT_LOOP/LINKTYPE_LOOP, 108 -- the
/// same layout, but the family value is always big-endian instead of DLT_NULL's host-order
/// ambiguity). A 4-byte address-family value (platform-specific, e.g. macOS AF_INET6=30 vs
/// FreeBSD=28), then directly the IP packet. The family value itself is never interpreted here --
/// `LaxSlicedPacket::from_ip` determines v4 vs v6 from the IP header's own version nibble, so all
/// that matters is skipping these 4 bytes, identical for both link types.
const NULL_LOOP_HEADER_LEN: usize = 4;

/// Parses one link-layer frame's bytes (as delivered by the capture format, e.g. Ethernet or
/// Linux cooked-capture for `any`) into a `TcpFrame`. Returns `Err(NotTcp)` for anything that
/// isn't a full, well-formed TCP/IP segment -- ARP, non-TCP transport, truncated captures, etc.
/// Not an error worth halting the whole capture over; callers should just skip these packets (see
/// `orchestrator.rs`), since there's nothing decodable in them regardless.
pub fn parse_tcp_frame(link_type: DataLink, data: &[u8]) -> Result<TcpFrame, ParseError> {
    use etherparse::{LaxNetSlice, LaxSlicedPacket, TransportSlice};

    let (sliced, base_offset) = match link_type {
        DataLink::ETHERNET => (
            LaxSlicedPacket::from_ethernet(data).map_err(|_| ParseError::NotTcp)?,
            0,
        ),
        DataLink::LINUX_SLL => {
            if data.len() < LINUX_SLL_HEADER_LEN {
                return Err(ParseError::NotTcp);
            }
            (
                LaxSlicedPacket::from_ip(&data[LINUX_SLL_HEADER_LEN..])
                    .map_err(|_| ParseError::NotTcp)?,
                LINUX_SLL_HEADER_LEN,
            )
        }
        DataLink::LINUX_SLL2 => {
            if data.len() < LINUX_SLL2_HEADER_LEN {
                return Err(ParseError::NotTcp);
            }
            (
                LaxSlicedPacket::from_ip(&data[LINUX_SLL2_HEADER_LEN..])
                    .map_err(|_| ParseError::NotTcp)?,
                LINUX_SLL2_HEADER_LEN,
            )
        }
        DataLink::RAW => (
            LaxSlicedPacket::from_ip(data).map_err(|_| ParseError::NotTcp)?,
            0,
        ),
        DataLink::NULL | DataLink::LOOP => {
            if data.len() < NULL_LOOP_HEADER_LEN {
                return Err(ParseError::NotTcp);
            }
            (
                LaxSlicedPacket::from_ip(&data[NULL_LOOP_HEADER_LEN..])
                    .map_err(|_| ParseError::NotTcp)?,
                NULL_LOOP_HEADER_LEN,
            )
        }
        _ => return Err(ParseError::NotTcp),
    };

    let (src_ip, dst_ip) = match sliced.net.as_ref().ok_or(ParseError::NotTcp)? {
        LaxNetSlice::Ipv4(ip) => (
            IpAddr::V4(ip.header().source_addr()),
            IpAddr::V4(ip.header().destination_addr()),
        ),
        LaxNetSlice::Ipv6(ip) => (
            IpAddr::V6(ip.header().source_addr()),
            IpAddr::V6(ip.header().destination_addr()),
        ),
        _ => return Err(ParseError::NotTcp),
    };

    let TransportSlice::Tcp(tcp) = sliced.transport.as_ref().ok_or(ParseError::NotTcp)? else {
        return Err(ParseError::NotTcp);
    };

    let payload = tcp.payload();
    // Safe: `payload` is a sub-slice of `&data[base_offset..]`, which is itself a sub-slice of
    // `data` -- both borrows are rooted in the same original buffer the caller owns.
    let payload_start = payload.as_ptr() as usize - data.as_ptr() as usize;
    let payload_range = payload_start..(payload_start + payload.len());
    let _ = base_offset; // only needed conceptually above; payload_start is computed via pointer arithmetic directly

    Ok(TcpFrame {
        src_ip,
        dst_ip,
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        seq: tcp.sequence_number(),
        ack_number: tcp.acknowledgment_number(),
        flags: TcpFlags {
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            ack: tcp.ack(),
            psh: tcp.psh(),
        },
        payload_range,
    })
}

/// One packet's raw bytes plus its index in the stream (for `reassembly::SourcePiece`
/// provenance) and its capture timestamp (epoch-relative -- `ek_output.rs` needs this for the
/// same `"timestamp"` field real tshark's `-T ek` output carries).
pub struct RawPacket {
    pub index: usize,
    pub data: Vec<u8>,
    pub timestamp: std::time::Duration,
}

/// A capture stream opened from either classic pcap or pcapng framing, dispatching
/// `next_packet()` transparently over whichever format matched.
pub enum PcapSource<R: Read> {
    Pcap {
        reader: PcapReader<R>,
        link_type: DataLink,
    },
    PcapNg {
        reader: PcapNgReader<R>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("could not read enough bytes to detect the capture format")]
    TooShort,
    #[error("unrecognized capture format (not classic pcap or pcapng magic)")]
    UnknownMagic,
    #[error("pcap/pcapng parse error: {0}")]
    Pcap(#[from] PcapError),
}

/// The 4 magic-detection bytes, re-chained in front of the rest of `R` so `open()`'s caller can
/// hand over a plain, not-yet-peeked reader (e.g. `stdin.lock()`) without needing to buffer or
/// seek it themselves.
type ChainedReader<R> = std::io::Chain<std::io::Cursor<Vec<u8>>, R>;

/// Detects classic pcap vs. pcapng from the first 4 bytes and returns a `PcapSource` wrapping
/// whichever format matched. Classic pcap magic: `0xA1B2C3D4`/`0xD4C3B2A1` (and their
/// nanosecond-resolution variants `0xA1B23C4D`/`0x4D3CB2A1`); pcapng: `0x0A0D0D0A` section header
/// magic (byte-order-independent -- it's a palindrome).
pub fn open<R: Read>(mut input: R) -> Result<PcapSource<ChainedReader<R>>, OpenError> {
    let mut magic = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        let n = input
            .read(&mut magic[filled..])
            .map_err(|_| OpenError::TooShort)?;
        if n == 0 {
            return Err(OpenError::TooShort);
        }
        filled += n;
    }
    let chained = std::io::Cursor::new(magic.to_vec()).chain(input);

    match magic {
        [0xA1, 0xB2, 0xC3, 0xD4]
        | [0xD4, 0xC3, 0xB2, 0xA1]
        | [0xA1, 0xB2, 0x3C, 0x4D]
        | [0x4D, 0x3C, 0xB2, 0xA1] => {
            let reader = PcapReader::new(chained)?;
            let link_type = reader.header().datalink;
            Ok(PcapSource::Pcap { reader, link_type })
        }
        [0x0A, 0x0D, 0x0D, 0x0A] => Ok(PcapSource::PcapNg {
            reader: PcapNgReader::new(chained)?,
        }),
        _ => Err(OpenError::UnknownMagic),
    }
}

/// One packet's bytes plus its link type (pcapng can, in principle, carry multiple interfaces
/// with different link types per Interface Description Block; classic pcap has exactly one,
/// fixed at the global header), or an error reading the next block from the underlying stream.
type NextPacketResult = Option<Result<(RawPacket, DataLink), OpenError>>;

impl<R: Read> PcapSource<R> {
    /// Reads the next raw packet's bytes, or `None` at clean EOF.
    pub fn next_packet(&mut self, index: usize) -> NextPacketResult {
        match self {
            PcapSource::Pcap { reader, link_type } => reader.next_packet().map(|r| {
                r.map(|p| {
                    (
                        RawPacket {
                            index,
                            data: p.data.into_owned(),
                            timestamp: p.timestamp,
                        },
                        *link_type,
                    )
                })
                .map_err(OpenError::from)
            }),
            PcapSource::PcapNg { reader } => loop {
                let block = match reader.next_block() {
                    None => return None,
                    Some(Err(e)) => return Some(Err(OpenError::from(e))),
                    Some(Ok(block)) => block,
                };
                if let Block::EnhancedPacket(epb) = block {
                    // Pull out owned values first: `epb` borrows from `reader`'s internal buffer
                    // (tied to the `&mut self` borrow `next_block()` took), so it must be fully
                    // consumed before `reader.interfaces()` (an immutable borrow) can be called.
                    let interface_id = epb.interface_id;
                    let data = epb.data.into_owned();
                    // `pcap-file` 2.0.0's own `EnhancedPacketBlock::timestamp` unconditionally
                    // assumes nanosecond resolution (`Duration::from_nanos(raw_ticks)`), silently
                    // ignoring the interface's actual declared `if_tsresol` -- wrong for any
                    // capture that isn't nanosecond-resolution (real captures overwhelmingly
                    // aren't; the pcapng spec's own default, when the option is absent, is
                    // microseconds). Recover the original raw tick count losslessly (`.as_nanos()`
                    // on a `Duration::from_nanos(x)` returns exactly `x`) and re-interpret it using
                    // the interface's real resolution -- see `correct_epb_timestamp`.
                    let mis_scaled_timestamp = epb.timestamp;
                    let interface = reader.interfaces().get(interface_id as usize);
                    let link_type = interface.map(|i| i.linktype).unwrap_or(DataLink::ETHERNET);
                    let if_tsresol = interface.and_then(|i| {
                        i.options.iter().find_map(|opt| match opt {
                            InterfaceDescriptionOption::IfTsResol(v) => Some(*v),
                            _ => None,
                        })
                    });
                    let timestamp = correct_epb_timestamp(mis_scaled_timestamp, if_tsresol);
                    return Some(Ok((
                        RawPacket {
                            index,
                            data,
                            timestamp,
                        },
                        link_type,
                    )));
                }
                // Non-packet blocks (section headers, interface descriptions, etc.) are skipped
                // transparently -- keep pulling until a real packet or EOF.
            },
        }
    }
}

/// Reconstructs the correct absolute timestamp from an `EnhancedPacketBlock`'s raw tick count
/// (recovered from `pcap-file`'s mis-scaled `Duration`, see the call site's doc comment), honoring
/// the interface's own declared resolution. `if_tsresol` per the pcapng spec: absent means the
/// default, microseconds (10^-6s); MSB clear means a power of 10 (`10^-value` seconds/tick, the
/// overwhelmingly common case); MSB set means a power of 2 (`2^-(value & 0x7F)` seconds/tick).
fn correct_epb_timestamp(mis_scaled: Duration, if_tsresol: Option<u8>) -> Duration {
    let raw_ticks = mis_scaled.as_nanos();
    let tsresol = if_tsresol.unwrap_or(6);
    if tsresol & 0x80 != 0 {
        let shift = (tsresol & 0x7F) as u32;
        let unit = 1u128 << shift;
        let whole_secs = (raw_ticks / unit) as u64;
        let frac_ticks = raw_ticks % unit;
        let subsec_nanos = (frac_ticks * 1_000_000_000 / unit) as u32;
        Duration::new(whole_secs, subsec_nanos)
    } else {
        // Values above 9 would mean sub-nanosecond ticks -- not representable in a `Duration`
        // (whose own finest unit is nanoseconds) and not anything a real capture tool emits;
        // clamping to 9 (nanoseconds) is a safe, conservative fallback rather than panicking or
        // silently overflowing.
        let exp = tsresol.min(9) as u32;
        let divisor = 10u128.pow(exp);
        let whole_secs = (raw_ticks / divisor) as u64;
        let frac_ticks = raw_ticks % divisor;
        let subsec_nanos = (frac_ticks * 10u128.pow(9 - exp)) as u32;
        Duration::new(whole_secs, subsec_nanos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{LinuxSllPacketType, PacketBuilder};
    use std::net::Ipv4Addr;

    fn build_ethernet_ipv4_tcp(
        seq: u32,
        flags: impl Fn(
            etherparse::PacketBuilderStep<etherparse::TcpHeader>,
        ) -> etherparse::PacketBuilderStep<etherparse::TcpHeader>,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(9410, 51234, seq, 65535);
        let builder = flags(builder);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    fn build_linux_sll_ipv4_tcp(seq: u32, payload: &[u8]) -> Vec<u8> {
        let builder =
            PacketBuilder::linux_sll(LinuxSllPacketType::OTHERHOST, 6, [1, 2, 3, 4, 5, 6, 0, 0])
                .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
                .tcp(9410, 51234, seq, 65535);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn parses_ethernet_ipv4_tcp_frame() {
        let data = build_ethernet_ipv4_tcp(1000, |b| b, b"hello");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert_eq!(frame.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(frame.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(frame.src_port, 9410);
        assert_eq!(frame.dst_port, 51234);
        assert_eq!(frame.seq, 1000);
        assert_eq!(&data[frame.payload_range], b"hello");
    }

    #[test]
    fn parses_linux_sll_ipv4_tcp_frame() {
        // Matches TCPDUMPER_IFACE=any in production -- tcpdump's Linux "cooked capture" pseudo
        // link type, not Ethernet.
        let data = build_linux_sll_ipv4_tcp(2000, b"world");
        let frame = parse_tcp_frame(DataLink::LINUX_SLL, &data).unwrap();
        assert_eq!(frame.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(frame.seq, 2000);
        assert_eq!(&data[frame.payload_range], b"world");
    }

    #[test]
    fn parses_linux_sll2_ipv4_tcp_frame() {
        // Real bytes from the first packet of a genuine production capture, captured via
        // `tcpdump -i any` and hex-dumped with `tshark -x` to confirm the exact header layout
        // empirically -- NOT the older 16-byte SLL v1 layout `parses_linux_sll_ipv4_tcp_frame`
        // above tests, but the 20-byte SLL2 layout (LINKTYPE_LINUX_SLL2/276) modern tcpdump
        // actually emits for `-i any`, which `capinfos` on that file reports as "Linux
        // cooked-mode capture v2". Missing this link type entirely would have caused every
        // packet in every real capture to silently fail to parse (caught during empirical
        // verification against real production data, not by any synthetic test -- exactly the
        // kind of gap synthetic fixtures alone don't catch).
        #[rustfmt::skip]
        let data: &[u8] = &[
            // SLL2 header (20 bytes): protocol_type=0x0800 (IPv4), reserved, interface_index=4,
            // arphrd_type=1 (Ethernet), packet_type=0 (host), addr_len=6, addr (8, padded)
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01,
            0x00, 0x06, 0x0a, 0xfb, 0xb2, 0x1e, 0x49, 0x1c, 0x00, 0x00,
            // IPv4 header (20 bytes, no options): src=100.100.103.249, dst=10.0.0.12
            0x45, 0x00, 0x00, 0x3c, 0xe1, 0xc2, 0x40, 0x00, 0x7b, 0x06,
            0x3a, 0x3d, 0x64, 0x64, 0x67, 0xf9, 0x0a, 0x9b, 0x0c, 0xc4,
            // TCP header: srcport=0x9408=37896, dstport=0x24c2=9410, seq=0x6da40a1f
            0x94, 0x08, 0x24, 0xc2, 0x6d, 0xa4, 0x0a, 0x1f, 0x00, 0x00,
            0x00, 0x00, 0xa0, 0x02, 0xf5, 0x07, 0xdc, 0xe1, 0x00, 0x00,
            0x02, 0x04, 0x21, 0x0c, 0x04, 0x02, 0x08, 0x0a, 0x77, 0xed,
            0xce, 0x86, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
        ];
        let frame = parse_tcp_frame(DataLink::LINUX_SLL2, data).unwrap();
        assert_eq!(frame.src_ip, IpAddr::V4(Ipv4Addr::new(100, 100, 103, 249)));
        assert_eq!(frame.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 155, 12, 196)));
        assert_eq!(frame.src_port, 37896);
        assert_eq!(frame.dst_port, 9410);
        assert_eq!(frame.seq, 0x6da40a1f);
        assert!(
            frame.flags.syn,
            "this real packet is a SYN (flags byte 0x02 = SYN only)"
        );
    }

    #[test]
    fn parses_bsd_loopback_null_ipv4_tcp_frame() {
        // Real bytes from the first packet of a genuine local capture on macOS's `lo0` (`tcpdump
        // -i lo0`), hex-dumped with `tshark -x` -- LINKTYPE_NULL/0, what every local
        // localhost-only capture on macOS/BSD uses. Missing this link type entirely made every
        // packet in such a capture silently fail to parse (0 TLS records seen at all), caught
        // empirically while testing against a real capture, not by any synthetic fixture.
        #[rustfmt::skip]
        let data: &[u8] = &[
            // DLT_NULL header (4 bytes): address family, host byte order (0x00000002 = AF_INET
            // on macOS/BSD; the exact value is never interpreted, see NULL_LOOP_HEADER_LEN's doc
            // comment -- only its 4-byte length matters).
            0x02, 0x00, 0x00, 0x00,
            // IPv4 header (20 bytes, no options): src=127.0.0.1, dst=127.0.0.1
            0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
            0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
            // TCP header: srcport=0xd69c=54940, dstport=0x24c2=9410, seq=0x9d9766f9
            0xd6, 0x9c, 0x24, 0xc2, 0x9d, 0x97, 0x66, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0xfe, 0x34, 0x00, 0x00,
            0x02, 0x04, 0x3f, 0xd8, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01,
            0x08, 0x0a, 0x2c, 0x32, 0x81, 0xce, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x02, 0x00, 0x00,
        ];
        let frame = parse_tcp_frame(DataLink::NULL, data).unwrap();
        assert_eq!(frame.src_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(frame.dst_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(frame.src_port, 54940);
        assert_eq!(frame.dst_port, 9410);
        assert_eq!(frame.seq, 0x9d9766f9);
        assert!(
            frame.flags.syn,
            "this real packet is a SYN (flags byte 0x02 = SYN only)"
        );
    }

    #[test]
    fn parses_bsd_loop_ipv4_tcp_frame_identically_to_null() {
        // DLT_LOOP/108 is the same 4-byte-header-then-IP layout as DLT_NULL/0 -- same real packet
        // bytes as parses_bsd_loopback_null_ipv4_tcp_frame (just the family header's byte order
        // flipped, though it's never actually interpreted), different link type, confirms both
        // are handled identically (NULL_LOOP_HEADER_LEN).
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x02,
            0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
            0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
            0xd6, 0x9c, 0x24, 0xc2, 0x9d, 0x97, 0x66, 0xf9, 0x00, 0x00,
            0x00, 0x00, 0xb0, 0x02, 0xff, 0xff, 0xfe, 0x34, 0x00, 0x00,
            0x02, 0x04, 0x3f, 0xd8, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01,
            0x08, 0x0a, 0x2c, 0x32, 0x81, 0xce, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x02, 0x00, 0x00,
        ];
        let frame = parse_tcp_frame(DataLink::LOOP, data).unwrap();
        assert_eq!(frame.src_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(frame.src_port, 54940);
        assert_eq!(frame.dst_port, 9410);
    }

    #[test]
    fn extracts_fin_and_rst_flags() {
        let data = build_ethernet_ipv4_tcp(1, |b| b.fin(), b"");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert!(frame.flags.fin);
        assert!(!frame.flags.rst);

        let data = build_ethernet_ipv4_tcp(1, |b| b.rst(), b"");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert!(frame.flags.rst);
        assert!(!frame.flags.fin);

        let data = build_ethernet_ipv4_tcp(1, |b| b.syn(), b"");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert!(frame.flags.syn);
    }

    #[test]
    fn extracts_ack_number_and_psh_flag() {
        // Not consulted by reassembly/eviction (unlike syn/fin/rst/ack) -- carried through purely
        // for orchestrator.rs's packet-level output events (see TcpFlags::psh's doc comment).
        let data = build_ethernet_ipv4_tcp(1, |b| b.ack(987654321).psh(), b"");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert!(frame.flags.ack);
        assert!(frame.flags.psh);
        assert_eq!(frame.ack_number, 987654321);

        let data = build_ethernet_ipv4_tcp(1, |b| b, b"");
        let frame = parse_tcp_frame(DataLink::ETHERNET, &data).unwrap();
        assert!(!frame.flags.psh);
    }

    #[test]
    fn non_tcp_frame_is_rejected_not_panicking() {
        // A bare, too-short buffer -- garbage/truncated capture data.
        assert!(parse_tcp_frame(DataLink::ETHERNET, &[0u8; 4]).is_err());
    }

    #[test]
    fn open_detects_classic_pcap_magic() {
        // Classic pcap global header: magic + version + timezone + sigfigs + snaplen + linktype.
        let mut bytes = vec![0xD4u8, 0xC3, 0xB2, 0xA1]; // little-endian magic
        bytes.extend_from_slice(&2u16.to_le_bytes()); // version_major
        bytes.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        bytes.extend_from_slice(&1u32.to_le_bytes()); // linktype = ETHERNET

        let source = open(std::io::Cursor::new(bytes)).unwrap();
        assert!(matches!(source, PcapSource::Pcap { .. }));
    }

    #[test]
    fn open_rejects_unknown_magic() {
        let bytes = vec![0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert!(matches!(
            open(std::io::Cursor::new(bytes)),
            Err(OpenError::UnknownMagic)
        ));
    }

    /// Regression test for a real bug caught while verifying the new `-T ndjson` output against
    /// real production captures: `pcap-file` 2.0.0's own `EnhancedPacketBlock::timestamp`
    /// unconditionally assumes nanosecond resolution, ignoring the interface's actual declared
    /// `if_tsresol` entirely -- every real production capture used elsewhere in this project
    /// declares microsecond resolution (the pcapng spec's own default when the option is absent),
    /// so every single timestamp tlscap ever emitted (in `-T ek` too, not just the new format) was
    /// silently wrong by orders of magnitude before this fix.
    #[test]
    fn corrects_microsecond_resolution_timestamp() {
        // 1_500_000 raw ticks at microsecond resolution = 1.5 seconds -- but pcap-file would have
        // hand us `Duration::from_nanos(1_500_000)` (1.5 MILLIseconds), which is what a caller
        // passes in here as `mis_scaled` to be corrected.
        let mis_scaled = Duration::from_nanos(1_500_000);
        let corrected = correct_epb_timestamp(mis_scaled, Some(6));
        assert_eq!(corrected, Duration::new(1, 500_000_000));
    }

    #[test]
    fn absent_if_tsresol_defaults_to_microseconds_per_pcapng_spec() {
        let mis_scaled = Duration::from_nanos(1_500_000);
        assert_eq!(
            correct_epb_timestamp(mis_scaled, None),
            Duration::new(1, 500_000_000)
        );
    }

    #[test]
    fn nanosecond_resolution_is_a_no_op() {
        // tsresol=9 means pcap-file's own hardcoded assumption happens to be correct -- confirms
        // the fix doesn't corrupt the one resolution `pcap-file` already gets right.
        let d = Duration::new(1, 500_000_000);
        assert_eq!(correct_epb_timestamp(d, Some(9)), d);
    }

    #[test]
    fn corrects_second_resolution_timestamp() {
        // tsresol=0 means 10^0 = 1 second per tick -- 5 raw ticks is 5 seconds, not 5ns.
        let mis_scaled = Duration::from_nanos(5);
        assert_eq!(
            correct_epb_timestamp(mis_scaled, Some(0)),
            Duration::new(5, 0)
        );
    }

    #[test]
    fn corrects_power_of_two_resolution_timestamp() {
        // tsresol=0x80 | 20 means 2^-20 seconds per tick (~954ns); 2^20 ticks is exactly 1 second.
        let ticks = 1u128 << 20;
        let mis_scaled = Duration::from_nanos(ticks as u64);
        assert_eq!(
            correct_epb_timestamp(mis_scaled, Some(0x80 | 20)),
            Duration::new(1, 0)
        );
    }
}
