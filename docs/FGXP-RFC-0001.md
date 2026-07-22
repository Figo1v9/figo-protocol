# FGXP-RFC-0001: FigoX Protocol Specification

```
Title:        FigoX Protocol (FGXP) — A Stealth Transport Protocol
Version:      1.0.0-draft
Status:       Draft
Authors:      FigoX Engineering Team
Created:      2026-07-18
Updated:      2026-07-18
Category:     Standards Track
```

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design Goals](#2-design-goals)
3. [Non-Goals](#3-non-goals)
4. [Complete Architecture](#4-complete-architecture)
5. [Layer Model](#5-layer-model)
6. [Binary Packet Format](#6-binary-packet-format)
7. [Frame Definitions](#7-frame-definitions)
8. [Session Lifecycle](#8-session-lifecycle)
9. [State Machine](#9-state-machine)
10. [Stream Multiplexing](#10-stream-multiplexing)
11. [Congestion Control API](#11-congestion-control-api)
12. [Flow Control](#12-flow-control)
13. [Plugin System](#13-plugin-system)
14. [Version Negotiation](#14-version-negotiation)
15. [Error Codes](#15-error-codes)
16. [Authentication](#16-authentication)
17. [Key Management](#17-key-management)
18. [TLS Integration](#18-tls-integration)
19. [Certificate Management](#19-certificate-management)
20. [Client Architecture](#20-client-architecture)
21. [Server Architecture](#21-server-architecture)
22. [SDK Design](#22-sdk-design)
23. [Go Project Structure](#23-go-project-structure)
24. [Deployment](#24-deployment)
25. [Benchmark Methodology](#25-benchmark-methodology)
26. [Stress Testing](#26-stress-testing)
27. [Integration Testing](#27-integration-testing)
28. [Fuzz Testing](#28-fuzz-testing)
29. [Security Review](#29-security-review)
30. [Threat Model](#30-threat-model)
31. [Roadmap](#31-roadmap)

---

## 1. Motivation

### 1.1 Problem Statement

Existing transport-layer obfuscation protocols (VMess, VLESS, Trojan, Shadowsocks, WireGuard, SOCKS5) share a fundamental weakness: **they all have identifiable fingerprints** that modern Deep Packet Inspection (DPI) systems can detect through statistical analysis, active probing, or protocol-specific signature matching.

```
┌──────────────────────────────────────────────────────────────────┐
│                    DPI Detection Methods                         │
├──────────────┬───────────────────────────────────────────────────┤
│ Method       │ Protocols Affected                                │
├──────────────┼───────────────────────────────────────────────────┤
│ Signature    │ VMess (header pattern), SOCKS5 (handshake bytes) │
│ Statistical  │ Shadowsocks (high entropy), WireGuard (UDP port) │
│ Active Probe │ VMess/VLESS (invalid auth → different behavior)  │
│ ML-Based     │ All protocols with consistent packet size/timing │
│ Whitelisting │ Any non-standard TLS (blocks unknown protocols)  │
└──────────────┴───────────────────────────────────────────────────┘
```

### 1.2 Why a New Protocol?

| Existing Protocol | Fundamental Limitation |
|---|---|
| VMess | Fixed 16-byte auth header creates detectable signature |
| VLESS | Simplified VMess; still identifiable via response pattern |
| Trojan | Relies on TLS only; no QUIC support; no traffic shaping |
| Shadowsocks | Uniform random entropy is itself a detectable fingerprint |
| WireGuard | Openly identifies as WireGuard; trivially blocked |
| obfs4 | "Look-like-nothing" approach fails against protocol whitelisting |

**FGXP's approach:** Rather than creating a new signature or attempting to look like random noise, FGXP **IS** a standard TLS 1.3/QUIC connection. The protocol embeds its custom framing entirely within the encrypted payload of standard TLS records. To any observer — passive DPI, active probing, or ML-based analysis — the traffic is indistinguishable from a normal HTTPS/HTTP3 session to a legitimate website.

### 1.3 Design Rationale

The key insight: **the strongest obfuscation is no obfuscation**. Instead of adding an obfuscation layer that can be detected, FGXP uses standard TLS 1.3 and QUIC exactly as they were designed, placing all protocol-specific data inside the encrypted tunnel where DPI cannot see it.

```
┌─────────────────────────────────────────────────────┐
│  Observer sees:                                      │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Standard TLS 1.3 ClientHello                   │ │
│  │  Standard TLS 1.3 ServerHello                   │ │
│  │  Standard encrypted Application Data records    │ │
│  │  Standard TLS record sizes and timing           │ │
│  └─────────────────────────────────────────────────┘ │
│                                                      │
│  Inside the encrypted tunnel (invisible to DPI):     │
│  ┌─────────────────────────────────────────────────┐ │
│  │  FGXP Authentication                            │ │
│  │  FGXP Stream Multiplexing                       │ │
│  │  FGXP Data Frames                               │ │
│  │  FGXP Control Frames                            │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

---

## 2. Design Goals

### 2.1 Primary Goals

| # | Goal | Metric | Rationale |
|---|------|--------|-----------|
| G1 | **Undetectable Traffic** | 0% detection rate by DPI | Core mission — traffic must be indistinguishable from HTTPS |
| G2 | **Active Probe Resistance** | Server responds as legitimate web server | Prevents server discovery via probing |
| G3 | **High Throughput** | >= 90% of raw TLS throughput | Protocol overhead must be negligible |
| G4 | **Low Latency** | <= 1ms added latency per hop | Must not degrade user experience |
| G5 | **Massive Scale** | 1M+ concurrent connections | Enterprise and infrastructure use |
| G6 | **Low Resource Usage** | <= 50MB base memory, <= 5% CPU at idle | Suitable for constrained environments |
| G7 | **Dual Transport** | TCP+TLS 1.3 and QUIC | Adapt to any network environment |
| G8 | **Session Resumption** | < 100ms reconnect | Handle network instability gracefully |
| G9 | **Modular Design** | All components swappable via interfaces | Extensibility without core changes |
| G10 | **Backward Compatible** | Version negotiation with graceful fallback | No breaking upgrades |

### 2.2 Secondary Goals

| # | Goal | Rationale |
|---|------|-----------|
| G11 | Stream Multiplexing | Multiple logical channels over single connection |
| G12 | Flow Control | Prevent fast sender from overwhelming slow receiver |
| G13 | Congestion Control | Pluggable algorithms (CUBIC, BBR) |
| G14 | Optional Compression | Reduce bandwidth when beneficial |
| G15 | Plugin System | Extend without core modification |
| G16 | Observability | Logging, metrics, distributed tracing |
| G17 | Clustering | Load balancing, high availability |
| G18 | Hot Reload | Configuration changes without restart |
| G19 | Zero Downtime Upgrade | Rolling upgrades in production |
| G20 | Security | Strong authentication, key management |

---

## 3. Non-Goals

| # | Explicitly Not a Goal | Reason |
|---|----------------------|--------|
| N1 | General-purpose VPN | FGXP is a transport protocol, not a full VPN stack |
| N2 | Replacing TLS | FGXP uses standard TLS; it does not implement its own crypto |
| N3 | Replacing QUIC | FGXP uses QUIC as a transport; it does not reimplement QUIC |
| N4 | GUI Client | Out of scope; SDK enables third-party GUIs |
| N5 | Mobile-specific optimizations | Deferred to future versions |
| N6 | Custom cryptographic algorithms | Uses only well-audited standard algorithms |
| N7 | Onion routing | Single-hop proxy, not multi-hop relay |

---

## 4. Complete Architecture

### 4.1 System Overview

```
                         ┌─────────────────────────────────┐
                         │        FGXP Architecture         │
                         └─────────────────────────────────┘

  ┌──────────┐                                          ┌──────────┐
  │          │    TLS 1.3 / QUIC (Standard)             │          │
  │  Client  │◄────────────────────────────────────────►│  Server  │
  │  (fgxp)  │    (looks like normal HTTPS to DPI)      │  (fgxp)  │
  │          │                                          │          │
  └────┬─────┘                                          └────┬─────┘
       │                                                     │
       │ FGXP SDK API                                        │ FGXP SDK API
       │                                                     │
  ┌────▼─────┐                                          ┌────▼─────┐
  │  User    │                                          │  Target  │
  │  Apps    │                                          │ Services │
  └──────────┘                                          └──────────┘


  ┌─────────────────────── Server Internal ──────────────────────┐
  │                                                               │
  │  ┌────────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐ │
  │  │  Listener  │  │ Auth     │  │ Stealth   │  │ Plugin    │ │
  │  │  (TCP/QUIC)│  │ Manager  │  │ Engine    │  │ System    │ │
  │  └──────┬─────┘  └────┬─────┘  └─────┬─────┘  └─────┬─────┘ │
  │         │              │              │              │       │
  │  ┌──────▼──────────────▼──────────────▼──────────────▼─────┐ │
  │  │                   Session Manager                        │ │
  │  │  ┌─────────────────────────────────────────────────────┐ │ │
  │  │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐     │ │ │
  │  │  │  │ Sess │ │ Sess │ │ Sess │ │ Sess │ │ ...  │     │ │ │
  │  │  │  │  #1  │ │  #2  │ │  #3  │ │  #4  │ │      │     │ │ │
  │  │  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──────┘     │ │ │
  │  │  │     │        │        │        │                    │ │ │
  │  │  │  ┌──▼────────▼────────▼────────▼──────────────────┐ │ │ │
  │  │  │  │         Stream Multiplexer                     │ │ │ │
  │  │  │  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐          │ │ │ │
  │  │  │  │  │Str #0│ │Str #1│ │Str #2│ │Str #N│          │ │ │ │
  │  │  │  │  └──────┘ └──────┘ └──────┘ └──────┘          │ │ │ │
  │  │  │  └────────────────────────────────────────────────┘ │ │ │
  │  │  └─────────────────────────────────────────────────────┘ │ │
  │  └─────────────────────────────────────────────────────────┘ │
  │                                                               │
  │  ┌────────────┐  ┌──────────┐  ┌───────────┐  ┌───────────┐ │
  │  │ Congestion │  │ Flow     │  │ Compress  │  │ Observ-   │ │
  │  │ Control    │  │ Control  │  │ Engine    │  │ ability   │ │
  │  └────────────┘  └──────────┘  └───────────┘  └───────────┘ │
  └───────────────────────────────────────────────────────────────┘
```

### 4.2 Data Flow

```
  Application Data
       │
       ▼
  ┌─────────────┐
  │  Compress   │  (optional, per-stream)
  │  (LZ4/Zstd) │
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Frame      │  Add FGXP header (16 bytes)
  │  Encoder    │  + Stream ID, Sequence, Flags
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Stealth    │  Add random padding
  │  Padding    │  Normalize packet sizes
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  Mux        │  Multiplex onto connection
  │  Scheduler  │  (priority-based)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  TLS 1.3    │  Standard TLS encryption
  │  or QUIC    │  (no custom crypto)
  └──────┬──────┘
         │
         ▼
    Network Wire
```

---

## 5. Layer Model

### 5.1 Protocol Stack

```
┌─────────────────────────────────────────────────────────┐
│  Layer 5: Application Interface                          │
│  SDK API, connection management, stream handles          │
│  Provides: net.Conn-compatible interface                 │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Stream Management                              │
│  Multiplexing, flow control, priority scheduling         │
│  Stream IDs: 32-bit (0 = control, 1+ = data)            │
│  Window size: configurable, default 256KB per stream     │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Framing & Stealth                              │
│  Binary frame encoding, padding, timing normalization    │
│  Frame header: 16 bytes fixed                            │
│  Max frame payload: 65535 bytes                          │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Session & Authentication                       │
│  PSK auth, session state, resumption tokens              │
│  Session ID: 128-bit random                              │
│  Resumption token: 256-bit, time-limited                 │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Secure Transport                               │
│  TCP + TLS 1.3  OR  QUIC                                 │
│  Standard implementations, no modifications              │
│  TLS: crypto/tls (Go stdlib)                             │
│  QUIC: quic-go library                                   │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Design Decision: Why 5 Layers?

**Options considered:**
1. 3 layers (Transport / Protocol / Application) — too coarse; stealth and session concerns would be entangled
2. 7 layers (OSI-like) — over-abstracted; unnecessary indirection
3. **5 layers** — each layer has exactly one concern; stealth is isolated from framing; session is isolated from transport

**Verdict:** 5 layers. Clean separation without over-engineering.

---

## 6. Binary Packet Format

### 6.1 Frame Header (16 bytes, fixed)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  Type |         Payload Length (16)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Stream ID (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (32)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Flags (8)  |  Pad Len (8)  |      Reserved (16)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 6.2 Field Definitions

| Field | Bits | Offset | Description |
|-------|------|--------|-------------|
| Version | 4 | 0 | Protocol version (0x1 = v1) |
| Type | 4 | 4 | Frame type (see section 7) |
| Payload Length | 16 | 8 | Length of payload + padding in bytes |
| Stream ID | 32 | 24 | Logical stream identifier |
| Sequence | 32 | 56 | Monotonically increasing per-stream counter |
| Flags | 8 | 88 | Bitfield flags (see 6.3) |
| Pad Length | 8 | 96 | Length of padding at end of payload |
| Reserved | 16 | 104 | Must be 0x0000; available for future use |

### 6.3 Flags Bitfield

```
Bit 0 (0x01): FIN        — Last frame for this stream
Bit 1 (0x02): COMPRESSED — Payload is compressed
Bit 2 (0x04): PRIORITY   — Frame carries priority data
Bit 3 (0x08): ACK        — Acknowledgment frame
Bit 4 (0x10): URGENT     — Bypass flow control
Bit 5 (0x20): ENCRYPTED  — Payload has additional encryption layer
Bit 6-7:      Reserved   — Must be 0
```

### 6.4 Complete Frame Layout

```
┌──────────────────────────────────────┐
│          Frame Header (16 bytes)     │
├──────────────────────────────────────┤
│          Payload (0..65535 bytes)    │
├──────────────────────────────────────┤
│          Padding (0..255 bytes)      │
└──────────────────────────────────────┘
```

### 6.5 Design Decisions

**Why 16-byte header?** Fits in a single cache line alongside small payloads. 4 bytes too small (no stream ID). 32 bytes unnecessary overhead.

**Why 16-bit payload length?** Keeps header at 16 bytes. 65KB frames are large enough for high throughput.

**Why 32-bit Stream ID?** Supports 2^31 concurrent streams. Bit 31 = direction (0=client, 1=server). Stream 0 reserved for control.

**Why 32-bit Sequence Number?** At 10Gbps with minimum frames, wraps in ~57 minutes. Wrap handling via stream reset.

---

## 7. Frame Definitions

### 7.1 Frame Type Registry

| Type | Value | Description | Payload |
|------|-------|-------------|---------|
| DATA | 0x0 | User data | Application bytes |
| CONTROL | 0x1 | Control metadata | Key-value pairs |
| WINDOW_UPDATE | 0x2 | Flow control credit | 4 bytes: increment |
| PING | 0x3 | Keepalive/latency probe | 8 bytes: opaque data |
| PONG | 0x4 | Ping response | 8 bytes: echo data |
| STREAM_OPEN | 0x5 | Open new stream | Stream metadata |
| STREAM_CLOSE | 0x6 | Graceful stream close | Optional error info |
| STREAM_RESET | 0x7 | Abrupt stream termination | 4 bytes: error code |
| GOAWAY | 0x8 | Session shutdown | 4+4 bytes: last stream + error |
| AUTH | 0x9 | Authentication exchange | Auth-specific data |
| SESSION_RESUME | 0xA | Resume prior session | 48 bytes: ID + token |
| CONFIG | 0xB | Configuration exchange | Key-value settings |
| RESERVED | 0xC-0xE | Reserved for future use | — |
| EXTENSION | 0xF | Plugin-defined frames | Plugin-specific |

### 7.2 AUTH Frame (0x9)

```
┌──────────────────── Header (16 bytes) ────────────────────┐
│ Ver=1 │ Type=0x9 │ PayloadLen │ StreamID=0 │ Seq │ Flags ││
├───────────────────────────────────────────────────────────┤
│  Auth Method (1 byte)                                     │
│  Auth Phase  (1 byte)                                     │
│  Auth Data   (variable)                                   │
└───────────────────────────────────────────────────────────┘

Auth Methods:
  0x01 = PSK (Pre-Shared Key)
  0x02 = HMAC-SHA256 Challenge-Response
  0x03 = Certificate-based (future)

Auth Phases:
  0x01 = INIT      (client sends auth request)
  0x02 = CHALLENGE (server sends challenge)
  0x03 = RESPONSE  (client sends response)
  0x04 = SUCCESS   (server confirms)
  0x05 = FAILURE   (server rejects)
```

### 7.3 WINDOW_UPDATE Frame (0x2)

```
Payload: 4 bytes — Window Increment (uint32)
StreamID = 0: connection-level flow control
StreamID > 0: stream-level flow control
Window increment MUST be > 0
Maximum window size: 2^31 - 1 bytes
```

### 7.4 CONFIG Frame (0xB)

```
Setting IDs:
  0x0001 = MAX_CONCURRENT_STREAMS    (default: 100)
  0x0002 = INITIAL_WINDOW_SIZE       (default: 262144 = 256KB)
  0x0003 = MAX_FRAME_PAYLOAD_SIZE    (default: 16384)
  0x0004 = COMPRESSION_ALGORITHM     (0=none, 1=lz4, 2=zstd)
  0x0005 = KEEPALIVE_INTERVAL_MS     (default: 30000)
  0x0006 = SESSION_TIMEOUT_MS        (default: 300000)
  0x0007 = STEALTH_PADDING_MODE      (0=none, 1=random, 2=normalized)
  0x0008 = MAX_HEADER_SIZE           (default: 8192)
```

---

## 8. Session Lifecycle

### 8.1 New Session Establishment

```
    Client                                          Server
      │                                               │
      │──────── TLS ClientHello ──────────────────────►│
      │◄─────── TLS ServerHello ──────────────────────│
      │◄─────── TLS Certificate ──────────────────────│
      │──────── TLS Finished ─────────────────────────►│
      │◄─────── TLS Finished ─────────────────────────│
      │                                               │
      │  ═══════ TLS Tunnel Established ═══════════   │
      │                                               │
      │──────── AUTH(INIT, PSK hash) ─────────────────►│
      │◄─────── AUTH(CHALLENGE, nonce) ───────────────│
      │──────── AUTH(RESPONSE, HMAC(nonce,PSK)) ──────►│
      │◄─────── AUTH(SUCCESS) + CONFIG ───────────────│
      │──────── CONFIG (client settings) ──────────────►│
      │                                               │
      │  ═══════ FGXP Session Active ══════════════   │
      │                                               │
      │──────── STREAM_OPEN(id=1) ────────────────────►│
      │──────── DATA(stream=1, payload) ──────────────►│
      │◄─────── DATA(stream=1, response) ─────────────│
```

### 8.2 Active Probe Response (Stealth Mode)

```
    Prober                                          Server
      │                                               │
      │──────── TLS ClientHello ──────────────────────►│
      │◄─────── TLS ServerHello ──────────────────────│
      │                                               │
      │  ═══════ TLS Tunnel Established ═══════════   │
      │                                               │
      │──────── "GET / HTTP/1.1\r\n..." ──────────────►│
      │                                               │
      │  (Server: first bytes are not AUTH frame)      │
      │  (Server: treat as regular HTTP request)       │
      │                                               │
      │◄─────── HTTP/1.1 200 OK (real webpage) ───────│
```

**Design Decision:** The server distinguishes FGXP clients from probers by inspecting the **first byte** after TLS handshake:
- If byte matches FGXP version nibble + AUTH type → proceed with FGXP
- If byte is HTTP method first character (G, P, H, D, O, C, T) → forward to camouflage
- Otherwise → close connection after sending HTTP 400

This is **timing-safe**: identical response time regardless of decision path.

---

## 9. State Machine

### 9.1 Session States

```
            ┌────────┐
            │  IDLE  │
            └───┬────┘
                │ connect()
                ▼
          ┌───────────┐
          │ CONNECTING│
          └─────┬─────┘
          ┌─────┴──────┐
     fail │            │ TLS established
          ▼            ▼
    ┌──────────┐ ┌──────────────┐
    │  FAILED  │ │AUTHENTICATING│
    └──────────┘ └──────┬───────┘
         ▲        ┌─────┴─────┐
         │   fail │           │ auth_ok
         │        ▼           ▼
         │  ┌──────────┐ ┌────────┐
         │  │  FAILED  │ │ ACTIVE │
         │  └──────────┘ └───┬────┘
         │              ┌────┴─────────┐
         │     goaway() │    error     │ idle_timeout
         │              ▼              ▼
         │        ┌──────────┐  ┌───────────┐
         │        │ DRAINING │  │RECONNECTING│
         │        └────┬─────┘  └─────┬──────┘
         │             │         ┌────┴────┐
         │             │    ok   │    fail  │
         │             │         ▼         ▼
         │             │   ┌────────┐ ┌──────────┐
         │             │   │ ACTIVE │ │  FAILED  │
         │             │   └────────┘ └──────────┘
         │             ▼                    │
         │       ┌──────────┐               │
         └───────│  CLOSED  │◄──────────────┘
                 └──────────┘
```

### 9.2 State Transitions

| Current State | Event | Next State | Action |
|---|---|---|---|
| IDLE | connect() | CONNECTING | Initiate TCP/QUIC + TLS |
| CONNECTING | TLS established | AUTHENTICATING | Send AUTH(INIT) |
| CONNECTING | timeout/error | FAILED | Log error, notify caller |
| AUTHENTICATING | AUTH(SUCCESS) | ACTIVE | Exchange CONFIG, ready |
| AUTHENTICATING | AUTH(FAILURE) | FAILED | Log, cleanup |
| ACTIVE | GOAWAY received | DRAINING | Stop new streams, finish existing |
| ACTIVE | goaway() called | DRAINING | Send GOAWAY, drain streams |
| ACTIVE | transport error | RECONNECTING | Attempt session resumption |
| DRAINING | all streams closed | CLOSED | Close transport |
| RECONNECTING | SESSION_RESUME ok | ACTIVE | Resume streams |
| RECONNECTING | resume failed | FAILED | Full reconnect or close |
| FAILED | close() | CLOSED | Cleanup all resources |

### 9.3 Stream States

```
           ┌────────┐
           │  IDLE  │
           └───┬────┘
               │ STREAM_OPEN
               ▼
           ┌────────┐
           │  OPEN  │
           └───┬────┘
          ┌────┴──────────┐
     FIN sent        FIN received
          ▼               ▼
    ┌──────────┐   ┌──────────┐
    │HALF_CLOSE│   │HALF_CLOSE│
    │  LOCAL   │   │  REMOTE  │
    └────┬─────┘   └────┬─────┘
         └──────┬───────┘
                ▼
          ┌──────────┐
          │  CLOSED  │
          └──────────┘

    (STREAM_RESET from any state → CLOSED)
```

---

## 10. Stream Multiplexing

### 10.1 Stream ID Allocation

```
Bit 31 (MSB): Direction
  0 = Client-initiated
  1 = Server-initiated

Special IDs:
  0x00000000 = Control stream (always open)
  0x00000001 = First client stream
  0x80000001 = First server stream
```

### 10.2 Scheduling Algorithm: Weighted Fair Queuing (WFQ)

Each stream `i` with weight `w_i` gets bandwidth share `w_i / sum(w_j)`.

```
Algorithm: NextFrame()
  1. For each active stream with pending data:
     Calculate virtual_time = bytes_sent / weight
  2. Select stream with lowest virtual_time
  3. Send one frame from that stream
  4. Update bytes_sent
  5. Check flow control window before sending
```

**Why WFQ?** Round-Robin treats all streams equally. WFQ ensures proportional bandwidth while preventing starvation. O(log n) via heap.

---

## 11. Congestion Control API

### 11.1 Interface

```go
type CongestionController interface {
    OnPacketSent(size int, sentTime time.Time)
    OnAcknowledged(size int, rtt time.Duration, ackTime time.Time)
    OnPacketLost(size int, sentTime time.Time)
    CongestionWindow() int
    CanSend(bytes int) bool
    SmoothedRTT() time.Duration
    Reset()
}
```

### 11.2 Built-in: CUBIC (default), BBR, None (for QUIC)

**When CC applies:**
- TCP transport: FGXP CC is ACTIVE (complements TCP's CC)
- QUIC transport: FGXP CC is DISABLED (QUIC handles it)

---

## 12. Flow Control

### 12.1 Two-Level Design

```
Connection-Level Window (Stream ID = 0):
  Total bytes across ALL streams. Default: 1MB. Max: 2GB.

Per-Stream Windows:
  Each stream has its own window. Default: 256KB.

Rule: Frame sent only if BOTH stream AND connection windows have capacity.
```

### 12.2 Auto-Tuning

```
consumed_rate = bytes_consumed / time_since_last_update
ideal_window = consumed_rate * 2 * smoothed_rtt
if ideal_window > current_window * 1.5:
  send WINDOW_UPDATE(min(ideal_window, MAX_WINDOW))
```

---

## 13. Plugin System

### 13.1 Plugin Interface

```go
type Plugin interface {
    Name() string
    Version() string
    Init(ctx context.Context, config map[string]any) error
    Close() error
}

// Optional hook interfaces:
type OnConnectHook interface { OnConnect(ctx context.Context, conn ConnInfo) error }
type OnAuthHook interface { OnAuth(ctx context.Context, id AuthIdentity) (AuthResult, error) }
type OnDataHook interface {
    OnDataSend(ctx context.Context, streamID uint32, data []byte) ([]byte, error)
    OnDataRecv(ctx context.Context, streamID uint32, data []byte) ([]byte, error)
}
type OnStreamOpenHook interface { OnStreamOpen(ctx context.Context, stream StreamInfo) error }
type OnStreamCloseHook interface { OnStreamClose(ctx context.Context, streamID uint32, err error) }
type OnDisconnectHook interface { OnDisconnect(ctx context.Context, sessionID string, err error) }
```

### 13.2 Execution Order

- Outgoing: Plugin A → Plugin B → ... → wire
- Incoming: wire → ... → Plugin B → Plugin A (reverse unwinding)
- Any hook returning error stops the chain

---

## 14. Version Negotiation

```
Version nibble (4 bits):
  0x0 = Reserved
  0x1 = Version 1 (this spec)
  0x2-0xE = Future
  0xF = Version negotiation

Rules:
  1. Header layout MUST NOT change across versions
  2. New frame types via EXTENSION (0xF)
  3. Unknown flags MUST be ignored
  4. Unknown CONFIG settings MUST be ignored
  5. Features deprecated for 2 major versions before removal
```

---

## 15. Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00000000 | NO_ERROR | Graceful shutdown |
| 0x00000001 | PROTOCOL_ERROR | Generic protocol violation |
| 0x00000002 | FRAME_SIZE_ERROR | Frame exceeds maximum |
| 0x00000003 | FRAME_FORMAT_ERROR | Malformed frame header |
| 0x00000004 | INVALID_VERSION | Unsupported version |
| 0x00000005 | INVALID_FRAME_TYPE | Unknown frame type |
| 0x00000006 | INVALID_STREAM_ID | Invalid stream ID |
| 0x00000007 | INVALID_SEQUENCE | Sequence out of order |
| 0x00000008 | COMPRESSION_ERROR | Compress/decompress failed |
| 0x00000100 | AUTH_REQUIRED | Not yet authenticated |
| 0x00000101 | AUTH_FAILED | Invalid credentials |
| 0x00000102 | AUTH_EXPIRED | Token expired |
| 0x00000103 | AUTH_METHOD_UNSUPPORTED | Auth method not supported |
| 0x00000200 | STREAM_CLOSED | Operation on closed stream |
| 0x00000201 | STREAM_REFUSED | Stream creation refused |
| 0x00000202 | STREAM_LIMIT_EXCEEDED | Too many concurrent streams |
| 0x00000300 | FLOW_CONTROL_ERROR | Window violated |
| 0x00000400 | TRANSPORT_ERROR | Transport failure |
| 0x00000401 | TLS_ERROR | TLS error |
| 0x00000402 | QUIC_ERROR | QUIC error |
| 0x00000500 | INTERNAL_ERROR | Unexpected internal error |
| 0x00000501 | RESOURCE_EXHAUSTED | Limits reached |
| 0x00000600 | PLUGIN_ERROR | Plugin error |
| 0x80000000+ | Application-defined | User error codes |

---

## 16. Authentication

### 16.1 PSK Authentication Flow

```
Phase 1 — INIT:
  Client sends: Auth Method (0x01), Key ID (SHA256(PSK)[0:8]), Client Nonce (32 bytes)

Phase 2 — CHALLENGE:
  Server sends: Server Nonce (32 bytes), Timestamp (8 bytes)

Phase 3 — RESPONSE:
  Client computes: proof = HMAC-SHA256(key=PSK, data=client_nonce||server_nonce||timestamp)
  Client sends: Proof (32 bytes)

Phase 4 — SUCCESS:
  Server sends: Session ID (16 bytes), Resumption Token (32 bytes), Token Expiry (8 bytes)
```

### 16.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| Replay prevention | Nonce + timestamp + dedup window |
| Credential protection | PSK never on wire; HMAC proof only |
| Timing safety | Constant-time HMAC comparison |
| Forward secrecy | TLS 1.3 ECDHE |
| Key rotation | Key ID allows multiple active keys |

---

## 17. Key Management

### 17.1 Key Derivation (HKDF)

```
auth_key       = HKDF-Expand-Label(PSK, "fgxp auth", "", 32)
session_key    = HKDF-Expand-Label(PSK, "fgxp session", session_id, 32)
resumption_key = HKDF-Expand-Label(PSK, "fgxp resume", session_id||timestamp, 32)
```

### 17.2 Key Rotation

Multiple active keys supported. Rotation: add new → distribute → wait → remove expired. Existing sessions NOT interrupted.

---

## 18. TLS Integration

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    MaxVersion: tls.VersionTLS13,
    NextProtos: []string{"h2", "http/1.1"}, // Look like normal HTTPS
    ServerName: "legitimate-website.com",     // Camouflage SNI
}
```

**Why standard TLS only?** Any modification creates a fingerprint. Standard TLS 1.3 is identical to every HTTPS site.

---

## 19. Certificate Management

- **Option A (Recommended):** Real certificates via Let's Encrypt / ACME
- **Option B:** Self-signed + pinning (weaker stealth)
- **SNI-based selection:** Server selects cert based on ClientHello SNI
- **Auto-renewal:** Background goroutine + ACME + hot-swap

---

## 20. Client Architecture

```go
client, err := fgxp.NewClient(fgxp.ClientConfig{
    ServerAddr: "example.com:443",
    Transport:  fgxp.TransportTCP,
    PSK:        []byte("shared-secret-key"),
    SNI:        "legitimate-website.com",
})

stream, err := client.OpenStream(ctx)
defer stream.Close()
stream.Write([]byte("hello"))
```

---

## 21. Server Architecture

```go
server, err := fgxp.NewServer(fgxp.ServerConfig{
    ListenAddr:     ":443",
    Transport:      fgxp.TransportBoth,
    TLSCert:        "/path/to/cert.pem",
    TLSKey:         "/path/to/key.pem",
    PSKStore:        pskStore,
    CamouflageMode: fgxp.CamouflageReverseProxy,
    CamouflageTarget: "http://real-website.local:8080",
})

server.OnStream(func(stream fgxp.Stream) {
    io.Copy(targetConn, stream)
})

server.ListenAndServe(ctx)
```

---

## 22. SDK Design

- **net.Conn compatibility:** Streams implement net.Conn
- **Context-first:** All blocking ops accept context.Context
- **Minimal surface:** Only expose what users need
- **Zero dependencies in public API:** Only stdlib types
- **Errors are values:** All errors implement fgxpError with codes

---

## 23. Go Project Structure

See implementation_plan.md for full directory tree.

---

## 24. Deployment

- **L4 Load Balancer:** TLS terminates at FGXP, not LB
- **Docker:** Multi-stage build, alpine base
- **Zero Downtime:** SO_REUSEPORT + GOAWAY drain + graceful shutdown
- **Health:** /healthz, /readyz, /metrics (separate port)

---

## 25-28. Testing

- **Benchmarks:** Throughput, latency, connection rate, memory per conn
- **Stress:** 10K connections, 24h stability, reconnection storms
- **Integration:** Full matrix: TCP/QUIC x IPv4/IPv6 x all frame types
- **Fuzz:** Frame decoder, auth parser, config parser, state machine

---

## 29. Security Review

All crypto is standard (TLS 1.3, HMAC-SHA256, HKDF, CSPRNG). No custom crypto. Security invariants: PSK never on wire, constant-time comparisons, timing-safe branching, sequence numbers prevent replay.

---

## 30. Threat Model

| Threat | Mitigation |
|--------|-----------|
| Passive DPI | Standard TLS 1.3, no custom extensions |
| Active probing | Camouflage server, timing-safe |
| Traffic analysis (size) | Random padding, normalization |
| Traffic analysis (timing) | Timing jitter, keepalive randomization |
| Replay attack | Nonce + timestamp + dedup window |
| PSK compromise | Key rotation, forward secrecy via TLS |
| Server compromise | Forward secrecy, minimal logging |
| DoS | Connection limits, rate limiting, GOAWAY |

---

## 31. Roadmap

- **v0.1.0:** Core protocol, TCP transport, PSK auth, basic stealth
- **v0.2.0:** Stream multiplexing, flow control, compression, plugins
- **v0.3.0:** QUIC transport, advanced stealth, session resumption
- **v0.4.0:** Observability, hot reload, congestion control
- **v0.5.0:** Clustering, load balancing, zero downtime upgrade
- **v1.0.0:** Security audit, full testing, stable API

---

## Appendix: Wire Example

```
DATA frame carrying "Hello, World!" on stream 1:

Offset  Hex                                         ASCII
0000    10 00 00 11 00 00 00 01 00 00 00 01 00 04 00 00  ................
0010    48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21 AB CD EF  Hello, World!...
0020    FF                                               .

Byte 0:     0x10 = Version 1 (0x1) | Type DATA (0x0)
Byte 1-2:   0x0011 = Payload length 17 (13 data + 4 padding)
Byte 3-6:   0x00000001 = Stream ID 1
Byte 7-10:  0x00000001 = Sequence 1
Byte 11:    0x00 = No flags
Byte 12:    0x04 = Padding length 4
Byte 13-14: 0x0000 = Reserved
Byte 15-27: "Hello, World!"
Byte 28-31: 0xABCDEFFF = Random padding
```
