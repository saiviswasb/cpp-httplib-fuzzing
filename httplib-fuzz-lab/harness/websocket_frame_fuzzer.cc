#include <iostream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstddef>
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // WebSocket header requires at least 2 bytes

    std::string input(reinterpret_cast<const char *>(data), size);
    httplib::detail::buffer_stream strm(input);

    httplib::WebSocketFrame frame;
    size_t max_payload_len = 65536; // Boundary value: 64KB max payload limit

    try {
        // Direct call to internal unreached WebSocket frame parser
        httplib::detail::read_websocket_frame(strm, frame, max_payload_len);
        
        // If frame is text, execute UTF-8 validator
        if (frame.opcode == httplib::WebSocketOpcode::Text && !frame.payload.empty()) {
            httplib::detail::is_valid_utf8(frame.payload);
        }
    } catch (const std::exception &) {
        // Gracefully catch standard parsing exceptions
    }

    return 0;
}
