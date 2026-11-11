#include <iostream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <cstring>

#include "httplib.h"

// Concrete in-memory stream wrapper matching exact httplib::Stream interface
class BufferStream : public httplib::Stream {
public:
    BufferStream(const uint8_t *data, size_t size)
        : data_(reinterpret_cast<const char *>(data)), size_(size), position_(0) {}

    bool is_readable() const override { return position_ < size_; }
    bool is_writable() const override { return false; }

    ssize_t read(char *ptr, size_t size) override {
        if (position_ >= size_) return -1;
        size_t read_bytes = (std::min)(size, size_ - position_);
        std::memcpy(ptr, data_ + position_, read_bytes);
        position_ += read_bytes;
        return static_cast<ssize_t>(read_bytes);
    }

    ssize_t write(const char *ptr, size_t size) override { return -1; }

    void get_remote_ip_and_port(std::string &ip, int &port) const override {}
    void get_local_ip_and_port(std::string &ip, int &port) const override {}

    bool wait_readable() const override { return true; }
    bool wait_writable() const override { return true; }
    socket_t socket() const override { return -1; }
    time_t duration() const override { return 0; }

private:
    const char *data_;
    size_t size_;
    size_t position_;
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    BufferStream strm(data, size);
    std::string out_body;
    httplib::Headers headers;

    try {
        // Exercise internal chunked HTTP body decoder
        httplib::detail::parse_chunked_body(
            strm,
            [&out_body](const char *buf, size_t len) {
                out_body.append(buf, len);
                return true;
            },
            headers
        );
    } catch (const std::exception &) {
        // Catch parsing/boundary exceptions gracefully
    }

    return 0;
}
