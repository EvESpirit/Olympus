#include "olympus/codec/v24919/gcm_udp_header.hpp"

namespace olympus::codec::v24919 {

bool sign_gcm_udp_packet(
    std::span<std::uint8_t> packet_bytes,
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> secret_key) noexcept {

    if (packet_bytes.size() < GCM_HEADER_SIZE || packet_bytes.size() > GCM_MAX_WIRE_MTU) {
        return false;
    }

    auto tag_span = packet_bytes.first<HMAC_SHA1_96_TAG_SIZE>();
    auto body_span = packet_bytes.subspan(HMAC_SHA1_96_TAG_SIZE);
    compute_hmac_sha1_96(secret_key, body_span, tag_span);
    return true;
}

bool verify_gcm_udp_packet(
    std::span<const std::uint8_t> packet_bytes,
    std::span<const std::uint8_t, HMAC_SHA1_KEY_SIZE> secret_key) noexcept {

    if (packet_bytes.size() < GCM_HEADER_SIZE || packet_bytes.size() > GCM_MAX_WIRE_MTU) {
        return false;
    }

    auto expected_tag = packet_bytes.first<HMAC_SHA1_96_TAG_SIZE>();
    auto body_span    = packet_bytes.subspan(HMAC_SHA1_96_TAG_SIZE);
    return verify_hmac_sha1_96(secret_key, body_span, expected_tag);
}

} // namespace olympus::codec::v24919
