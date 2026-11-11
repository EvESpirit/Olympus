# Project Olympus (`Athena` & `Chiron`)

**Project Olympus** is a clean-room, multiplatform (**Windows + Linux**) **C++20** Dedicated Server suite for Overwatch Beta `0.8.0.24919` (`GameClientApp.exe`), built on a strict hexagonal architecture with zero client-side header dependencies.

---

## Architecture Overview

1. **`olympus::codec::v24919` (`include/olympus/codec/v24919/`, `src/codec/v24919/`) — Edge Wire Codec**
   - Isolates all `0.8.0.24919` binary wire details from the server core:
     - **JAM Compact Binary Reflection Codec (`+0xF2CE00` / `+0xF2C7D0`)**: Table-driven serializer/deserializer operating on `.data` `JAMMessageDesc` (`0x20` bytes) and `JAMFieldDesc` (`0x28` bytes) schemas, including bit-packed consecutive `bool` fields (`0x03`), fixed arrays `T[N]`, dynamic `teList<T>`, and nested sub-schemas (`0x0E`).
     - **Native `Game Connection Manager` (`+0xE51F70`) UDP Framing**: Exact `0x22`-byte (`34`-byte) `NativeGCMUdpHeader` (`12`-byte `HMAC-SHA1-96` tag, `28`-bit Session Token + `4`-bit packet type mask, sliding-window `seq_num` / `ack_num` / `window_state`, `SYN/ACK/FIN` handshake flags) with `1336`-byte maximum wire MTU (`0x538`) and 16-channel delivery token tracking (`channel_tokens[16]`).
     - **6-Sub-Channel Simulation Bitstream Multiplexer (`+0xC700A0` / `+0xC72C3C`)**: Bit-level packer/unpacker for `ClientSimulationNetworkManager` Sub-Channels `0..5`.
2. **`olympus::athena` (`include/olympus/athena/`, `src/athena/`) — Plane 1: Control Plane**
   - Handles TCP + TLS Battle.net Aurora (`bgs.protocol.*`) RPCs (port `1119`), Pool `0` automatic Compact Binary negotiation (`+0xF2A600`), 31 Lobby JAM Protocol Pools (`ClientLobbyMessageSystem_C`: `ClientInLobbyConnect` `0x4DEC`, Hero Gallery & `STUSkinTheme` progression), and match instance provisioning via **`ClientInLobbyInstance` (`0x5078`)**.
3. **`olympus::chiron` (`include/olympus/chiron/`, `src/chiron/`) — Plane 2: Simulation Plane**
   - Protocol-agnostic **Sparse-Set / Archetype ECS Core** ticking at a parameterized fixed timestep (default **`62.5 Hz` / `16.0 ms`**, scalable to `125 Hz` / `250 Hz`).
   - Owns authoritative movement validation (`Component_12` / `Component_15`), hybrid hit registration (`ClientInCombat` `0x61A8` / `0x61B1`), ability/sub-entity lifecycles, first-class server-owned Dummy Bots, and 64-tick circular delta compression.

# This repository is brand-new. Features are being developed almost daily. Do not use this unless you already know what you're doing. For now.
---

## Building (Windows & Linux)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```
