// websocket_frame_fuzzer.cc - fuzzes cpp-httplib's WebSocket frame parser.
//
// Targets (all in httplib::ws::impl, unreached by every upstream fuzzer):
//   read_websocket_frame()   RFC 6455 frame header, extended lengths, masking
//   is_valid_utf8()          text-frame payload validation
//   is_valid_close_payload() close-frame status code + reason validation
//
// Input layout:
//   byte 0, bit 7     expect_masked (1 = server side, peers must mask)
//   byte 0, bits 0-2  max_len bucket, see kMaxLen (boundary values)
//   bytes 1..n        raw bytes as they would arrive on the socket
//
// WebSocket support is compiled in by default; no macro is needed.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#include <httplib.h>

namespace {

// In-memory replacement for a socket. Only read() matters for the frame
// parser; the other methods satisfy the pure virtuals of httplib::Stream.
class FuzzedStream : public httplib::Stream {
public:
  FuzzedStream(const uint8_t *data, size_t size) : data_(data), size_(size) {}

  ssize_t read(char *ptr, size_t size) override {
    if (pos_ >= size_) { return 0; }  // EOF: read_exact() turns this into Fail
    size_t n = (std::min)(size, size_ - pos_);
    std::memcpy(ptr, data_ + pos_, n);
    pos_ += n;
    return static_cast<ssize_t>(n);
  }
  ssize_t write(const char *, size_t size) override {
    return static_cast<ssize_t>(size);  // pretend writes succeed
  }
  bool is_readable() const override { return pos_ < size_; }
  bool wait_readable() const override { return true; }
  bool wait_writable() const override { return true; }
  void get_remote_ip_and_port(std::string &ip, int &port) const override {
    ip = "127.0.0.1";
    port = 8080;
  }
  void get_local_ip_and_port(std::string &ip, int &port) const override {
    ip = "127.0.0.1";
    port = 8080;
  }
  socket_t socket() const override { return 0; }  // socket_t is global
  time_t duration() const override { return 0; }

private:
  const uint8_t *data_;
  size_t size_;
  size_t pos_ = 0;
};

// Boundary values for max_len, taken from the length checks in
// read_websocket_frame(): 0 = "no limit", 125 = largest 7-bit length,
// 126 = first 16-bit length, 65535/65536 = 16-bit/64-bit edge.
constexpr size_t kMaxLen[] = {0, 125, 126, 65535, 65536, 16u * 1024 * 1024};
constexpr int kMaxFrames = 64;     // bound the work per input
constexpr size_t kMaxMessage = 1u << 20;  // bound reassembled text size

void run(const uint8_t *data, size_t size) {
  using httplib::ws::Opcode;
  using httplib::ws::impl::FrameRead;

  const bool expect_masked = (data[0] & 0x80) != 0;
  const size_t max_len = kMaxLen[(data[0] & 0x07) % (sizeof(kMaxLen) / sizeof(kMaxLen[0]))];
  FuzzedStream strm(data + 1, size - 1);

  std::string message;  // text message reassembled across continuation frames
  bool in_text = false;

  for (int i = 0; i < kMaxFrames; i++) {
    Opcode opcode = Opcode::Continuation;
    std::string payload;
    bool fin = false;
    if (httplib::ws::impl::read_websocket_frame(strm, opcode, payload, fin,
                                                expect_masked, max_len) !=
        FrameRead::Ok) {
      break;
    }

    switch (opcode) {
    case Opcode::Text:
      in_text = !fin;
      message = payload;
      if (fin) { (void)httplib::ws::impl::is_valid_utf8(message); }
      break;
    case Opcode::Continuation:
      if (in_text && message.size() + payload.size() <= kMaxMessage) {
        message += payload;
        if (fin) {
          (void)httplib::ws::impl::is_valid_utf8(message);
          in_text = false;
        }
      }
      break;
    case Opcode::Close:
      (void)httplib::ws::impl::is_valid_close_payload(payload);
      return;  // a close frame ends the connection
    default:
      break;   // Binary, Ping, Pong, reserved opcodes: parser already ran
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) { return 0; }  // config byte + 2-byte minimal frame header
  try {
    run(data, size);
  } catch (const std::exception &) {
    // The parser is not expected to throw. Build with
    // -DHARNESS_STRICT_EXCEPTIONS during triage to turn this into a crash.
#ifdef HARNESS_STRICT_EXCEPTIONS
    std::abort();
#endif
  } catch (...) {
#ifdef HARNESS_STRICT_EXCEPTIONS
    std::abort();
#endif
  }
  return 0;
}
