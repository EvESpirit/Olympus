#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

#include "olympus/athena/athena_server.hpp"
#include "olympus/chiron/chiron_server.hpp"
#include "olympus/codec/v24919/bitstream.hpp"
#include "olympus/codec/v24919/gcm_udp_header.hpp"
#include "olympus/codec/v24919/hmac_sha1_96.hpp"
#include "olympus/codec/v24919/jam_compact_codec.hpp"

using namespace olympus;
using namespace olympus::codec::v24919;

static void test_gcm_header_and_hmac() {
    static_assert(sizeof(NativeGCMUdpHeader) == 0x22, "Header must be 34 bytes");

    std::array<std::uint8_t, HMAC_SHA1_KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(0xA0u + i);
    }

    std::vector<std::uint8_t> pkt(GCM_HEADER_SIZE + 16u, 0u);
    auto* hdr = reinterpret_cast<NativeGCMUdpHeader*>(pkt.data());
    hdr->set_session_and_type(0x0ABCDEFull, GCMPacketType::SequencedSimulation);
    hdr->seq_num = 42u;
    hdr->ack_num = 41u;
    hdr->window_state = 0xFFFFFFFFFFFFFFFFull;
    hdr->control_flags = GCMControlFlags::ACK;

    assert(hdr->session_token() == 0x0ABCDEFull);
    assert(hdr->packet_type() == GCMPacketType::SequencedSimulation);

    const bool signed_ok = sign_gcm_udp_packet(pkt, key);
    assert(signed_ok);
    assert(verify_gcm_udp_packet(pkt, key));

    // Tamper with 1 bit of payload -> verification must fail
    pkt.back() ^= 0x01u;
    assert(!verify_gcm_udp_packet(pkt, key));
}

static void test_jam_bit_packed_bools_and_0x5078() {
    JAMCompactWriter writer;
    // 8 consecutive booleans must pack into exactly 1 byte (+0xF2C916)
    const bool flags[8] = {true, false, true, true, false, false, true, false};
    for (bool b : flags) {
        writer.write_bool(b);
    }
    assert(writer.bytes().size() == 1u);

    // Non-bool resets bit_pos
    writer.write_u32(0x12345678u);
    assert(writer.bytes().size() == 5u);

    JAMCompactReader reader(writer.bytes());
    for (bool expected : flags) {
        bool actual = false;
        assert(reader.read_bool(actual) && actual == expected);
    }
    std::uint32_t u32_val = 0;
    assert(reader.read_u32(u32_val) && u32_val == 0x12345678u);

    // Round-trip Athena -> Chiron ClientInLobbyInstance (0x5078)
    athena::AthenaServer athena{};
    std::array<std::uint8_t, HMAC_SHA1_KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i + 1u);
    }
    auto handoff_out = athena.build_instance_handoff(0xCAFEBABE12345678ull, 0x07654321u, key);

    JAMCompactWriter handoff_writer;
    handoff_out.serialize_compact(handoff_writer);

    JAMCompactReader handoff_reader(handoff_writer.bytes());
    JAM_ClientInLobbyInstance_0x5078 handoff_in{};
    assert(handoff_in.deserialize_compact(handoff_reader));
    assert(handoff_in.m_instanceId == 0xCAFEBABE12345678ull);
    assert(handoff_in.m_address == "127.0.0.1");
    assert(handoff_in.m_udpPort == 26503);
    assert(handoff_in.m_connectionToken == 0x07654321u);
    assert(std::memcmp(handoff_in.m_secretKey, key.data(), HMAC_SHA1_KEY_SIZE) == 0);
}

static void test_bitstream_subchannel_header() {
    BitStreamWriter writer;
    // Simulate Sub-Channel 0: 1-bit has_jam_section = 1, 4-bit reliable = 3, 4-bit unreliable = 1,
    // plus Phase 2: 7-bit replicated_entity_count = 12 (total = 16 bits = 2 bytes)
    assert(writer.write_bit(true));
    assert(writer.write_bits(3u, 4u));
    assert(writer.write_bits(1u, 4u));
    assert(writer.write_bits(12u, 7u));
    assert(writer.bytes().size() == 2u);

    BitStreamReader reader(writer.bytes());
    bool has_jam = false;
    std::uint64_t rel = 0, unrel = 0, ent_cnt = 0;
    assert(reader.read_bit(has_jam) && has_jam);
    assert(reader.read_bits(4u, rel) && rel == 3u);
    assert(reader.read_bits(4u, unrel) && unrel == 1u);
    assert(reader.read_bits(7u, ent_cnt) && ent_cnt == 12u);
}

int main() {
    test_gcm_header_and_hmac();
    test_jam_bit_packed_bools_and_0x5078();
    test_bitstream_subchannel_header();
    std::printf("[PASS] All olympus::codec::v24919 wire-protocol verification tests succeeded.\n");
    return 0;
}
