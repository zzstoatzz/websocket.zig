const std = @import("std");

const libc = std.c;
const posix = std.posix;

// 0.16: std.Thread.sleep removed, use libc nanosleep
fn sleep(ns: u64) void {
    const secs = ns / std.time.ns_per_s;
    const nsecs = ns % std.time.ns_per_s;
    var ts: libc.timespec = .{
        .sec = @intCast(secs),
        .nsec = @intCast(nsecs),
    };
    _ = libc.nanosleep(&ts, null);
}
const ascii = std.ascii;
const Allocator = std.mem.Allocator;
const websocket = @import("../websocket.zig");

const M = @This();

const SpecialHeader = enum {
    none,
    upgrade,
    connection,
    @"sec-websocket-key",
    @"sec-websocket-version",
    @"sec-websocket-extensions",
};

pub const Handshake = struct {
    url: []const u8,
    key: []const u8,
    method: []const u8,
    headers: *KeyValue,
    res_headers: *KeyValue,
    raw_header: []const u8,
    compression: ?Compression,

    pub const Pool = M.Pool;

    pub const Compression = struct {
        client_no_context_takeover: bool,
        server_no_context_takeover: bool,
    };

    /// Incrementally parse an HTTP/1.1 request from `state.buf[0..state.len]`.
    ///
    /// Return values:
    ///   - `null`              — more data needed to make a decision
    ///   - `Some(Handshake)`   — valid RFC 6455 upgrade request
    ///   - `error.MissingHeaders` — well-formed HTTP/1.1 request that is NOT a
    ///     websocket upgrade. Held back until the request body (per
    ///     Content-Length) has fully arrived, so the worker's `httpFallback`
    ///     sees a complete request rather than a truncated one.
    ///   - other named errors  — request is malformed beyond recovery; the
    ///     worker responds 400.
    ///
    /// Streaming: end-of-headers is detected by `std.http.HeadParser`, a
    /// stdlib SIMD state machine that handles every TCP-fragmentation
    /// boundary correctly (including splits *inside* CRLF and CRLFCRLF
    /// sequences). The parser feeds only new bytes per call, so repeated
    /// calls as the buffer grows are O(new_bytes), not O(buf).
    ///
    /// RFC compliance:
    ///   - whitespace between header name and ':' is rejected per
    ///     RFC 7230 §3.2 (request smuggling vector)
    ///   - simultaneous Transfer-Encoding and Content-Length is rejected
    ///     per RFC 7230 §3.3 (request smuggling vector)
    ///   - obsolete line folding (RFC 7230 §3.2.4) is not supported;
    ///     a folded continuation line will surface as InvalidHeader
    ///   - request bodies with Transfer-Encoding only (no Content-Length)
    ///     are passed through to httpFallback without the worker
    ///     waiting for body completeness — chunked decoding is the
    ///     fallback handler's responsibility, not this parser's.
    ///
    /// Crash discipline (per Zig zen "runtime crashes are better than bugs"):
    ///   four invariant-protected paths use `unreachable` so a contract
    ///   violation surfaces as a debuggable panic rather than a silent
    ///   misclassification of valid input as malformed. all other error
    ///   paths correspond to genuinely malformed external input.
    pub fn parse(state: *State) !?Handshake {
        // Phase 1: streaming detection of end-of-headers via std.http.HeadParser.
        // feed only NEW bytes since last call so the SIMD scan is amortized.
        const newly_arrived = state.buf[state.head_fed..state.len];
        state.head_fed += state.head_parser.feed(newly_arrived);
        if (state.head_parser.state != .finished) return null;

        // Phase 2: parse the bounded request.
        // body_start = head_fed = position of first body byte (just past CRLFCRLF).
        // Structure:
        //   REQUEST_LINE \r\n
        //   HEADER_LINE  \r\n      (zero or more)
        //   \r\n                   (blank line)
        //   [body]
        const body_start = state.head_fed;
        // HeadParser .finished means it consumed at least the 4-byte CRLFCRLF.
        if (body_start < 4) unreachable;

        // Any buffer of length ≥4 ending in CRLFCRLF contains at least one CRLF.
        const first_crlf = std.mem.indexOf(u8, state.buf[0..body_start], "\r\n") orelse unreachable;
        const request_line = state.buf[0..first_crlf];

        if (!ascii.endsWithIgnoreCase(request_line, "http/1.1")) {
            return error.InvalidProtocol;
        }

        // headers accumulator. parse may be called multiple times on the
        // same state (e.g. while waiting for body bytes), so reset to keep
        // re-runs idempotent.
        var headers = &state.req_headers;
        headers.len = 0;

        var key: []const u8 = "";
        var required_headers: u8 = 0;
        var compression: ?Handshake.Compression = null;

        // header lines occupy [first_crlf + 2 .. body_start - 2], excluding
        // the blank line's CRLF. each line ends in CRLF (RFC 7230 §3.2.4
        // line folding deprecated; we don't support it).
        var rest = state.buf[first_crlf + 2 .. body_start - 2];
        while (rest.len > 0) {
            // rest is bounded by HeadParser's CRLFCRLF detection: every
            // line in it ends in CRLF, so indexOf must find one.
            const crlf = std.mem.indexOf(u8, rest, "\r\n") orelse unreachable;
            const line = rest[0..crlf];
            rest = rest[crlf + 2 ..];

            // HeadParser stops at the FIRST empty line, so an empty line
            // mid-iteration would mean rest was constructed wrong.
            if (line.len == 0) unreachable;

            // Leading whitespace = obsolete line folding (RFC 7230 §3.2.4)
            // OR malformed header. Both are rejected.
            if (ascii.isWhitespace(line[0])) return error.InvalidHeader;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
            if (colon == 0) return error.InvalidHeader; // empty name

            // RFC 7230 §3.2: "No whitespace is allowed between the header
            // field-name and colon. Servers MUST reject ... with a 400."
            // This is a request-smuggling defense, not stylistic.
            if (ascii.isWhitespace(line[colon - 1])) return error.WhitespaceBeforeColon;

            const name = toLower(line[0..colon]);
            const value = std.mem.trim(u8, line[colon + 1 ..], &ascii.whitespace);

            headers.add(name, value);
            switch (std.meta.stringToEnum(SpecialHeader, name) orelse .none) {
                .upgrade => {
                    if (!ascii.eqlIgnoreCase("websocket", value)) {
                        return error.InvalidUpgrade;
                    }
                    required_headers |= 1;
                },
                .connection => {
                    // Connection: keep-alive, Upgrade — the spec allows multiple tokens
                    if (std.ascii.indexOfIgnoreCase(value, "upgrade") == null) {
                        return error.InvalidConnection;
                    }
                    required_headers |= 4;
                },
                .@"sec-websocket-key" => {
                    key = value;
                    required_headers |= 8;
                },
                .@"sec-websocket-version" => {
                    if (value.len != 2 or value[0] != '1' or value[1] != '3') {
                        return error.InvalidVersion;
                    }
                    required_headers |= 2;
                },
                .@"sec-websocket-extensions" => compression = try parseExtension(value),
                .none => {},
            }
        }

        // RFC 7230 §3.3: simultaneous Transfer-Encoding and Content-Length is
        // a request-smuggling vector. The two headers can disagree about
        // body length, letting an attacker hide a second request inside the
        // first. Reject before any body-completeness logic runs.
        if (headers.get("transfer-encoding") != null and headers.get("content-length") != null) {
            return error.AmbiguousBodyLength;
        }

        if (required_headers != 15) {
            // Not a websocket upgrade. Before signalling MissingHeaders
            // (which triggers httpFallback dispatch in the worker), verify
            // the declared body has fully arrived — otherwise fallback
            // would see a truncated body.
            if (headers.get("content-length")) |cl_str| {
                const content_length = std.fmt.parseInt(usize, cl_str, 10) catch {
                    return error.MissingHeaders;
                };
                const body_available = state.len - body_start;
                if (body_available < content_length) {
                    // body not yet complete — ask caller for more data
                    return null;
                }
            }
            return error.MissingHeaders;
        }

        // request line: METHOD <space> URL <space> HTTP/1.1
        const sp = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.InvalidRequestLine;
        const method = request_line[0..sp];
        // url is between method-end and " HTTP/1.1" suffix (9 trailing chars)
        if (request_line.len < sp + 1 + 9) return error.InvalidRequestLine;
        const url = std.mem.trim(u8, request_line[sp + 1 .. request_line.len - 9], &ascii.whitespace);

        return .{
            .key = key,
            .url = url,
            .method = method,
            .headers = headers,
            .compression = compression,
            .res_headers = &state.res_headers,
            // raw_header preserves original byte-exact slice. matches the
            // pre-rewrite contract: starts after the request line's CRLF
            // and ends just past the last header's CRLF (i.e. excludes
            // the blank line's CRLF). callers re-emit this verbatim.
            .raw_header = state.buf[first_crlf + 2 .. body_start - 2],
        };
    }

    pub fn createReply(key: []const u8, headers_: ?*KeyValue, compression: bool, buf: []u8) ![]const u8 {
        const HEADER =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: ";

        @memcpy(buf[0..HEADER.len], HEADER);
        var pos = HEADER.len;

        {
            var h: [20]u8 = undefined;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(key);
            // websocket spec always used this value
            hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            hasher.final(&h);

            const end = pos + 28;
            _ = std.base64.standard.Encoder.encode(buf[pos..end], h[0..]);
            pos = end;
        }

        if (compression) {
            const permessage_deflate =
                "\r\nSec-WebSocket-Extensions: permessage-deflate" ++
                "; server_no_context_takeover" ++
                "; client_no_context_takeover";

            const end = pos + permessage_deflate.len;
            @memcpy(buf[pos..end], permessage_deflate);
            pos = end;
        }

        if (headers_) |headers| {
            for (headers.keys[0..headers.len], headers.values[0..headers.len]) |k, v| {
                pos += (try std.fmt.bufPrint(buf[pos..], "\r\n{s}: {s}", .{ k, v })).len;
            }
        }

        const end = pos + 4;
        @memcpy(buf[pos..end], "\r\n\r\n");
        return buf[0..end];
    }

    pub fn parseExtension(value: []const u8) !?Handshake.Compression {
        var deflate = false;
        var server_max_bits: u8 = 15;
        var client_no_context_takeover = false;
        var server_no_context_takeover = false;

        var it = std.mem.splitScalar(u8, value, ';');
        while (it.next()) |param_| {
            const param = std.mem.trim(u8, param_, &ascii.whitespace);
            if (std.mem.eql(u8, param, "permessage-deflate")) {
                deflate = true;
                continue;
            }
            if (std.mem.eql(u8, param, "client_no_context_takeover")) {
                client_no_context_takeover = true;
                continue;
            }
            if (std.mem.eql(u8, param, "server_no_context_takeover")) {
                server_no_context_takeover = true;
                continue;
            }
            const server_max_window_bits = "server_max_window_bits=";
            if (std.mem.startsWith(u8, param, server_max_window_bits)) {
                server_max_bits = std.fmt.parseInt(u8, param[server_max_window_bits.len..], 10) catch {
                    return error.InvalidCompressionServerMaxBits;
                };
            }
        }
        if (deflate == false) {
            return null;
        }

        if (server_max_bits != 15) {
            // Zig doesn't support a sliding deflate window. If the client asks
            // for a sliding window < 15, we can't accomodate it. This logic
            // should be pushed into the worker, but putting it here makes it
            // easier for any integration to also use this (i..e httz)
            return null;
        }

        return .{
            .client_no_context_takeover = client_no_context_takeover,
            .server_no_context_takeover = server_no_context_takeover,
        };
    }

    // This is what we're pooling
    pub const State = struct {
        // length of data we have in buf
        len: usize = 0,

        // a buffer to read data into
        buf: []u8,

        // streaming end-of-headers detector. advances across multiple
        // parse() calls as new bytes arrive. survives splits inside CRLF
        // sequences (the recurring class of TCP-fragmentation bugs).
        head_parser: std.http.HeadParser = .{},

        // monotonically tracks how many bytes have been fed into
        // head_parser. on each parse() call we feed only the new bytes
        // [head_fed..len] so the SIMD scan is amortized.
        head_fed: usize = 0,

        // Headers from the request
        req_headers: KeyValue,

        // Headers that we want to send in the response
        res_headers: KeyValue,

        pool: *M.Pool,

        fn init(pool: *M.Pool) !State {
            const allocator = pool.allocator;
            const buf = try allocator.alloc(u8, pool.buffer_size);
            errdefer allocator.free(buf);

            const req_headers = try Handshake.KeyValue.init(allocator, pool.max_req_headers);
            errdefer req_headers.deinit(allocator);

            const res_headers = try Handshake.KeyValue.init(allocator, pool.max_res_headers);
            errdefer res_headers.deinit(allocator);

            return .{
                .buf = buf,
                .pool = pool,
                .req_headers = req_headers,
                .res_headers = res_headers,
            };
        }

        fn deinit(self: *State) void {
            const allocator = self.pool.allocator;
            allocator.free(self.buf);
            self.req_headers.deinit(allocator);
            self.res_headers.deinit(allocator);
        }

        pub fn release(self: *State) void {
            self.len = 0;
            self.head_parser = .{};
            self.head_fed = 0;
            self.req_headers.len = 0;
            self.res_headers.len = 0;
            self.pool.release(self);
        }
    };

    pub const KeyValue = struct {
        len: usize,
        keys: [][]const u8,
        values: [][]const u8,

        fn init(allocator: Allocator, max: usize) !KeyValue {
            const keys = try allocator.alloc([]const u8, max);
            errdefer allocator.free(keys);

            const values = try allocator.alloc([]const u8, max);
            errdefer allocator.free(values);

            return .{
                .len = 0,
                .keys = keys,
                .values = values,
            };
        }

        fn deinit(self: *const KeyValue, allocator: Allocator) void {
            allocator.free(self.keys);
            allocator.free(self.values);
        }

        pub fn add(self: *KeyValue, key: []const u8, value: []const u8) void {
            const len = self.len;
            var keys = self.keys;
            if (len == keys.len) {
                return;
            }

            keys[len] = key;
            self.values[len] = value;
            self.len = len + 1;
        }

        pub fn get(self: *const KeyValue, needle: []const u8) ?[]const u8 {
            const keys = self.keys[0..self.len];
            loop: for (keys, 0..) |key, i| {
                // This is largely a reminder to myself that std.mem.eql isn't
                // particularly fast. Here we at least avoid the 1 extra ptr
                // equality check that std.mem.eql does, but we could do better
                // TODO: monitor https://github.com/ziglang/zig/issues/8689
                if (needle.len != key.len) {
                    continue;
                }
                for (needle, key) |n, k| {
                    if (n != k) {
                        continue :loop;
                    }
                }
                return self.values[i];
            }

            return null;
        }

        pub fn iterator(self: *const KeyValue) Iterator {
            const len = self.len;
            return .{
                .pos = 0,
                .keys = self.keys[0..len],
                .values = self.values[0..len],
            };
        }

        pub const Iterator = struct {
            pos: usize,
            keys: [][]const u8,
            values: [][]const u8,

            const KV = struct {
                key: []const u8,
                value: []const u8,
            };

            pub fn next(self: *Iterator) ?KV {
                const pos = self.pos;
                if (pos == self.keys.len) {
                    return null;
                }

                self.pos = pos + 1;
                return .{
                    .key = self.keys[pos],
                    .value = self.values[pos],
                };
            }
        };
    };
};

pub const Pool = struct {
    mutex: std.Io.Mutex,
    io: std.Io,
    available: usize,
    allocator: Allocator,
    buffer_size: usize,
    max_req_headers: usize,
    max_res_headers: usize,
    states: []*Handshake.State,

    pub fn init(allocator: Allocator, count: usize, buffer_size: usize, max_req_headers: usize, max_res_headers: usize) !*Pool {
        const states = try allocator.alloc(*Handshake.State, count);
        errdefer allocator.free(states);

        const pool = try allocator.create(Pool);
        errdefer allocator.destroy(pool);

        pool.* = .{
            .mutex = .init,
            .io = std.Options.debug_io,
            .states = states,
            .allocator = allocator,
            .available = count,
            .buffer_size = buffer_size,
            .max_req_headers = max_req_headers,
            .max_res_headers = max_res_headers,
        };

        for (0..count) |i| {
            const state = try allocator.create(Handshake.State);
            errdefer allocator.destroy(state);

            state.* = try Handshake.State.init(pool);
            states[i] = state;
        }

        return pool;
    }

    pub fn deinit(self: *Pool) void {
        const allocator = self.allocator;
        for (self.states) |s| {
            s.deinit();
            allocator.destroy(s);
        }
        allocator.free(self.states);
        allocator.destroy(self);
    }

    pub fn acquire(self: *Pool) !*Handshake.State {
        const states = self.states;
        const io = self.io;

        self.mutex.lockUncancelable(io);
        const available = self.available;
        if (available == 0) {
            // dont hold the lock over factory
            self.mutex.unlock(io);

            const allocator = self.allocator;
            const state = try allocator.create(Handshake.State);
            errdefer allocator.destroy(state);
            state.* = try Handshake.State.init(self);
            return state;
        }
        const index = available - 1;
        const state = states[index];
        self.available = index;
        self.mutex.unlock(io);
        return state;
    }

    fn release(self: *Pool, state: *Handshake.State) void {
        var states = self.states;
        const io = self.io;

        self.mutex.lockUncancelable(io);
        const available = self.available;
        if (available == states.len) {
            self.mutex.unlock(io);
            state.deinit();
            self.allocator.destroy(state);
            return;
        }
        states[available] = state;
        self.available = available + 1;
        self.mutex.unlock(io);
    }
};

fn toLower(str: []u8) []u8 {
    for (str, 0..) |c, i| {
        str[i] = ascii.toLower(c);
    }
    return str;
}

const t = @import("../t.zig");
test "handshake: parse" {
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    {
        var state = try pool.acquire();
        defer state.release();

        try t.expectEqual(null, try testHandshake("", state));
        try t.expectEqual(null, try testHandshake("GET", state));
        try t.expectEqual(null, try testHandshake("GET 1 HTTP/1.0\r", state));
        try t.expectEqual(null, try testHandshake("GET 1 HTTP/1.0\r\n", state));

        try t.expectError(error.InvalidProtocol, testHandshake("GET / HTTP/1.0\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection:  upgrade\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n", state));
        try t.expectError(error.MissingHeaders, testHandshake("GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\n\r\n", state));
    }

    {
        var state = try pool.acquire();
        defer state.release();

        const h = (try testHandshake("GET /test?a=1   HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: 9000!\r\nCustom:  Header-Value\r\n\r\n", state)).?;
        try t.expectString("9000!", h.key);
        try t.expectString("GET", h.method);
        try t.expectString("/test?a=1", h.url);
        try t.expectString("connection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: 9000!\r\ncustom:  Header-Value\r\n", h.raw_header);
        try t.expectString("Header-Value", h.headers.get("custom").?);

        var it = h.headers.iterator();
        {
            const kv = it.next().?;
            try t.expectString("connection", kv.key);
            try t.expectString("upgrade", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("upgrade", kv.key);
            try t.expectString("websocket", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("sec-websocket-version", kv.key);
            try t.expectString("13", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("sec-websocket-key", kv.key);
            try t.expectString("9000!", kv.value);
        }

        {
            const kv = it.next().?;
            try t.expectString("custom", kv.key);
            try t.expectString("Header-Value", kv.value);
        }

        try t.expectEqual(null, it.next());
    }
}

test "handshake: parse — every byte-split of a valid upgrade is equivalent" {
    // Regression net for the recurring class of TCP-fragmentation bugs.
    // For a known-good request, feeding it 1-byte-at-a-time, 2-bytes-at-a-time,
    // etc. must produce the same final outcome as feeding it whole.
    // This catches any future parser change that loses idempotence under
    // partial reads — including splits inside CRLF or CRLFCRLF sequences.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    const req = "GET /chat HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: abc\r\n\r\n";

    var chunk: usize = 1;
    while (chunk <= req.len) : (chunk += 1) {
        var state = try pool.acquire();
        defer state.release();

        const h = (try testHandshakeIncremental(req, chunk, state)) orelse {
            std.debug.print("chunk={d}: parse returned null instead of Handshake\n", .{chunk});
            return error.UnexpectedNull;
        };
        try t.expectString("abc", h.key);
        try t.expectString("GET", h.method);
        try t.expectString("/chat", h.url);
    }
}

test "handshake: parse — split inside CRLF and CRLFCRLF sequences" {
    // Pin specific torture-cases that have caused production outages:
    //   - split between '\r' and '\n' of the request-line CRLF
    //   - split between request-line's CRLF and the next header's first byte
    //   - split inside the final CRLFCRLF (each of the 4 internal positions)
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    const req = "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: k\r\n\r\n";

    // Try every two-chunk split. Each split must produce the same handshake.
    var split: usize = 1;
    while (split < req.len) : (split += 1) {
        var state = try pool.acquire();
        defer state.release();

        state.head_parser = .{};
        state.head_fed = 0;
        state.req_headers.len = 0;
        state.len = 0;

        // first chunk
        @memcpy(state.buf[0..split], req[0..split]);
        state.len = split;
        const r1 = try Handshake.parse(state);
        try t.expectEqual(null, r1);

        // second chunk
        @memcpy(state.buf[split..req.len], req[split..]);
        state.len = req.len;
        const h = (try Handshake.parse(state)).?;
        try t.expectString("k", h.key);
    }
}

test "handshake: parse — malformed inputs return errors, never panic" {
    // Adversarial / malformed inputs should map to named errors. There
    // must be no `unreachable` reachable from any input; every parse
    // exits via either Some(handshake), null, or a named error.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    const Case = struct { input: []const u8, expected: anyerror };
    const cases = [_]Case{
        // request line missing space → InvalidRequestLine after protocol check
        .{ .input = "GETONLY\r\n\r\n", .expected = error.InvalidProtocol },
        .{ .input = "GETONLY HTTP/1.1\r\n\r\n", .expected = error.MissingHeaders },
        // request line ends mid-protocol
        .{ .input = "GET / HTTP/1\r\n\r\n", .expected = error.InvalidProtocol },
        // header line with no colon
        .{ .input = "GET / HTTP/1.1\r\nNoColonHere\r\n\r\n", .expected = error.InvalidHeader },
        // header with empty name
        .{ .input = "GET / HTTP/1.1\r\n: value\r\n\r\n", .expected = error.InvalidHeader },
        // upgrade present but not "websocket"
        .{ .input = "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: nope\r\n\r\n", .expected = error.InvalidUpgrade },
        // version not 13
        .{ .input = "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version: 12\r\n\r\n", .expected = error.InvalidVersion },
        // connection without "upgrade" token
        .{ .input = "GET / HTTP/1.1\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n", .expected = error.InvalidConnection },
    };

    for (cases) |c| {
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(c.expected, testHandshake(c.input, state));
    }
}

test "handshake: parse — POST body byte-split equivalence" {
    // The headline bug from b45400c: POST with body split across reads
    // must hold null until the full body has arrived, then return
    // MissingHeaders so the worker dispatches httpFallback with the
    // complete body. Testing every possible split position guards
    // against any future regression in the body-completeness path.
    var pool = try Pool.init(t.allocator, 1, 1024, 10, 1);
    defer pool.deinit();

    const req = "POST /xrpc/com.atproto.sync.requestCrawl HTTP/1.1\r\nHost: relay\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"hostname\":\"pds.test.com\"}";

    var split: usize = 1;
    while (split < req.len) : (split += 1) {
        var state = try pool.acquire();
        defer state.release();

        state.head_parser = .{};
        state.head_fed = 0;
        state.req_headers.len = 0;
        state.len = 0;

        @memcpy(state.buf[0..split], req[0..split]);
        state.len = split;
        // first call: must NOT commit to MissingHeaders before body arrives
        const r1 = Handshake.parse(state) catch |e| blk: {
            // legitimate early errors (bad request line) are fine
            if (e != error.InvalidProtocol and e != error.InvalidRequestLine) return e;
            break :blk @as(?Handshake, null);
        };
        try t.expectEqual(null, r1);

        @memcpy(state.buf[split..req.len], req[split..]);
        state.len = req.len;
        try t.expectError(error.MissingHeaders, Handshake.parse(state));
    }
}

test "handshake: parse — RFC 7230 §3.2 rejects whitespace before colon" {
    // "No whitespace is allowed between the header field-name and colon.
    //  Servers must reject ... with a 400." This is a request-smuggling
    //  defense, not stylistic.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    const cases = [_][]const u8{
        // single space before colon
        "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
        // tab before colon
        "GET / HTTP/1.1\r\nHost\t: x\r\n\r\n",
        // also catches it on a non-required header
        "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: x\r\nFoo : bar\r\n\r\n",
    };

    for (cases) |c| {
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(error.WhitespaceBeforeColon, testHandshake(c, state));
    }
}

test "handshake: parse — RFC 7230 §3.3 rejects Transfer-Encoding + Content-Length" {
    // Combination is a request-smuggling vector. RFC says either reject or
    // remove Content-Length before forwarding; we choose explicit rejection
    // because we can't safely forward what we don't trust.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    {
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(
            error.AmbiguousBodyLength,
            testHandshake(
                "POST /x HTTP/1.1\r\nHost: r\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
                state,
            ),
        );
    }

    {
        // also rejects when both appear on a (would-be) WS upgrade
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(
            error.AmbiguousBodyLength,
            testHandshake(
                "GET / HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: x\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                state,
            ),
        );
    }
}

test "handshake: parse — rejects obsolete line folding (RFC 7230 §3.2.4)" {
    // "A sender MUST NOT generate a message that includes line folding."
    // We surface a folded continuation as InvalidHeader rather than try
    // to reconstruct the obs-fold semantics.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    var state = try pool.acquire();
    defer state.release();
    // continuation line starts with whitespace — would be folded value of "Host"
    try t.expectError(
        error.InvalidHeader,
        testHandshake("GET / HTTP/1.1\r\nHost: r\r\n continued\r\n\r\n", state),
    );
}

test "handshake: parse — idempotent under repeated calls without new bytes" {
    // Calling parse twice in a row with the same state.len must produce
    // the same answer. Otherwise the worker can race with itself when
    // it polls before another byte arrives.
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    var state = try pool.acquire();
    defer state.release();

    const req = "GET /a HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\nsec-websocket-version:13\r\nsec-websocket-key: x\r\n\r\n";
    @memcpy(state.buf[0..req.len], req);
    state.len = req.len;

    const h1 = (try Handshake.parse(state)).?;
    const h2 = (try Handshake.parse(state)).?;
    try t.expectString(h1.key, h2.key);
    try t.expectString(h1.method, h2.method);
    try t.expectString(h1.url, h2.url);
}

test "handshake: parse POST with body signals MissingHeaders (for httpFallback)" {
    var pool = try Pool.init(t.allocator, 1, 512, 10, 1);
    defer pool.deinit();

    {
        // POST whose body has arrived in the same read as the headers.
        // Must surface MissingHeaders (so the worker dispatches to httpFallback)
        // — NOT return null (which would loop forever waiting for more data).
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(
            error.MissingHeaders,
            testHandshake(
                "POST /xrpc/com.atproto.sync.requestCrawl HTTP/1.1\r\nHost: relay\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"hostname\":\"pds.test.com\"}",
                state,
            ),
        );
    }

    {
        // POST whose body has NOT fully arrived yet — parse must return null
        // so the worker reads more data before dispatching the fallback.
        var state = try pool.acquire();
        defer state.release();
        try t.expectEqual(
            null,
            try testHandshake(
                "POST /x HTTP/1.1\r\nHost: r\r\nContent-Length: 100\r\n\r\n{\"only\":\"part\"}",
                state,
            ),
        );
    }

    {
        // POST with no Content-Length and headers terminated — surface
        // MissingHeaders immediately, no body expected.
        var state = try pool.acquire();
        defer state.release();
        try t.expectError(
            error.MissingHeaders,
            testHandshake("POST /x HTTP/1.1\r\nHost: r\r\n\r\n", state),
        );
    }
}

test "handshake: reply" {
    var buf: [512]u8 = undefined;

    {
        // no compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", null, false, &buf));
    }

    {
        // compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", null, true, &buf));
    }

    // With custom headers
    var res_headers = try Handshake.KeyValue.init(t.allocator, 2);
    defer res_headers.deinit(t.allocator);
    res_headers.add("Set-Cookie", "Yummy!");

    {
        // no compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Set-Cookie: Yummy!\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", &res_headers, false, &buf));
    }

    {
        // compression
        const expected =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: upgrade\r\n" ++
            "Sec-Websocket-Accept: flzHu2DevQ2dSCSVqKSii5e9C2o=\r\n" ++
            "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
            "Set-Cookie: Yummy!\r\n\r\n";
        try t.expectString(expected, try Handshake.createReply("this is my key", &res_headers, true, &buf));
    }
}

test "KeyValue: get" {
    const allocator = t.allocator;
    var kv = try Handshake.KeyValue.init(allocator, 2);
    defer kv.deinit(t.allocator);

    var key = "content-type".*;
    kv.add(&key, "application/json");

    try t.expectString("application/json", kv.get("content-type").?);

    kv.len = 0;
    try t.expectEqual(null, kv.get("content-type"));
    kv.add(&key, "application/json2");
    try t.expectString("application/json2", kv.get("content-type").?);
}

test "KeyValue: ignores beyond max" {
    var kv = try Handshake.KeyValue.init(t.allocator, 2);
    defer kv.deinit(t.allocator);

    var n1 = "content-length".*;
    kv.add(&n1, "cl");

    var n2 = "host".*;
    kv.add(&n2, "www");

    var n3 = "authorization".*;
    kv.add(&n3, "hack");

    try t.expectString("cl", kv.get("content-length").?);
    try t.expectString("www", kv.get("host").?);
    try t.expectEqual(null, kv.get("authorization"));
}

test "pool: acquire and release" {
    // not 100% sure this is testing exactly what I want, but it's ....something ?
    var p = try Pool.init(t.allocator, 2, 10, 3, 1);
    defer p.deinit();

    var hs1a = p.acquire() catch unreachable;
    var hs2a = p.acquire() catch unreachable;
    var hs3a = p.acquire() catch unreachable; // this should be dynamically generated

    try t.expectEqual(false, &hs1a.buf[0] == &hs2a.buf[0]);
    try t.expectEqual(false, &hs2a.buf[0] == &hs3a.buf[0]);
    try t.expectEqual(10, hs1a.buf.len);
    try t.expectEqual(10, hs2a.buf.len);
    try t.expectEqual(10, hs3a.buf.len);
    try t.expectEqual(0, hs1a.req_headers.len);
    try t.expectEqual(0, hs2a.req_headers.len);
    try t.expectEqual(0, hs3a.req_headers.len);
    try t.expectEqual(3, hs1a.req_headers.keys.len);
    try t.expectEqual(3, hs2a.req_headers.keys.len);
    try t.expectEqual(3, hs3a.req_headers.keys.len);

    p.release(hs1a);

    var hs1b = p.acquire() catch unreachable;
    try t.expectEqual(true, &hs1a.buf[0] == &hs1b.buf[0]);

    p.release(hs3a);
    p.release(hs2a);
    p.release(hs1b);
}

test "Handshake.Pool: threadsafety" {
    var p = try Pool.init(t.allocator, 4, 10, 2, 2);
    defer p.deinit();

    for (p.states) |hs| {
        hs.buf[0] = 0;
    }

    const t1 = try std.Thread.spawn(.{}, testPool, .{p});
    const t2 = try std.Thread.spawn(.{}, testPool, .{p});
    const t3 = try std.Thread.spawn(.{}, testPool, .{p});
    const t4 = try std.Thread.spawn(.{}, testPool, .{p});

    t1.join();
    t2.join();
    t3.join();
    t4.join();
}

fn testPool(p: *Pool) void {
    var r = t.getRandom();
    const random = r.random();

    for (0..5000) |_| {
        var hs = p.acquire() catch unreachable;
        std.debug.assert(hs.buf[0] == 0);
        hs.buf[0] = 255;
        sleep(random.uintAtMost(u32, 100000));
        hs.buf[0] = 0;
        p.release(hs);
    }
}

fn testHandshake(request: []const u8, state: *Handshake.State) !?Handshake {
    // simulate a fresh socket: clear streaming parse state before pushing
    // a new request. existing tests reuse one State across many distinct
    // requests for convenience, which would otherwise wedge head_parser
    // in whatever state the previous request left it in.
    state.head_parser = .{};
    state.head_fed = 0;
    state.req_headers.len = 0;
    @memcpy(state.buf[0..request.len], request);
    state.len = request.len;
    return Handshake.parse(state);
}

/// Feed the request `chunk_size` bytes at a time, asserting that all
/// non-final calls return null. Returns the result of the final parse.
/// This is the core regression-test mechanism for TCP-split bugs:
/// any parser that's correct under all-at-once must also be correct
/// under every possible byte-split arrival pattern.
fn testHandshakeIncremental(request: []const u8, chunk_size: usize, state: *Handshake.State) !?Handshake {
    state.head_parser = .{};
    state.head_fed = 0;
    state.req_headers.len = 0;
    state.len = 0;

    var fed: usize = 0;
    while (fed < request.len) {
        const take = @min(chunk_size, request.len - fed);
        @memcpy(state.buf[state.len .. state.len + take], request[fed .. fed + take]);
        state.len += take;
        fed += take;
        if (fed < request.len) {
            // not the last chunk yet — parser must not commit either way
            const r = Handshake.parse(state) catch |e| {
                // an early error is allowed only if the request is
                // detectably malformed regardless of remaining bytes
                // (e.g. wrong HTTP version in the request line).
                return e;
            };
            if (r != null) {
                // committing to success before the request is fully delivered
                // would be a bug — at minimum it would race with body bytes
                // for non-upgrade requests.
                return error.PrematureSuccess;
            }
        }
    }
    return Handshake.parse(state);
}
