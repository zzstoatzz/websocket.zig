const std = @import("std");
const proto = @import("../proto.zig");
const buffer = @import("../buffer.zig");

const ascii = std.ascii;
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const tls = std.crypto.tls;
const log = std.log.scoped(.websocket);

const Reader = proto.Reader;
const Allocator = std.mem.Allocator;
const Bundle = std.crypto.Certificate.Bundle;
const CompressionOpts = @import("../websocket.zig").Compression;
const ServerHandshake = @import("../server/handshake.zig").Handshake;

fn milliTimestamp(io: Io) i64 {
    const ts = Io.Timestamp.now(io, .real);
    return @intCast(@divTrunc(ts.nanoseconds, std.time.ns_per_ms));
}

fn ReadLoopHandler(comptime T: type) type {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => |struct_info| {
            if (struct_info.is_tuple)
                @compileError("readLoop: handler does not support tuples.");

            return T;
        },
        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .one => return ReadLoopHandler(ptr_info.child),
                else => @compileError("readLoop: handler does not support Slice, C and Many pointers."),
            }
        },
        else => @compileError("readLoop: expected handler to be a struct or pointer to a struct but found '" ++ @tagName(info) ++ "'"),
    }
}

pub const Client = struct {
    io: Io,
    stream: Stream,
    _reader: Reader,
    _closed: bool,
    _compression_opts: ?CompressionOpts,
    _compression: ?Client.Compression = null,

    // Serializes writes from concurrent tasks (ping loop, auto-pong, close).
    // Matches server-side Conn.lock pattern.
    _write_lock: Io.Mutex = .init,

    // When creating a client, we can either be given a BufferProvider or create
    // one ourselves. If we create it ourselves (in init), we "own" it and must
    // free it on deinit. (The reference to the buffer provider is already in the
    // reader, no need to hold another reference in the client).
    _own_bp: bool,

    // For advanced cases, a custom masking function can be provided. Masking
    // is a security feature that only really makes sense in the browser. If you
    // aren't running websockets in the browser AND you control both the client
    // and the server, you could get a performance boost by not masking.
    _mask_fn: *const fn (Io) [4]u8,

    pub const Config = struct {
        port: u16,
        host: []const u8,
        tls: bool = false,
        max_size: usize = 65536,
        buffer_size: usize = 4096,
        ca_bundle: ?Bundle = null,
        mask_fn: ?*const fn (Io) [4]u8 = null,
        buffer_provider: ?*buffer.Provider = null,
        compression: ?CompressionOpts = null,
    };

    pub const HandshakeOpts = struct {
        timeout_ms: u32 = 10000,
        headers: ?[]const u8 = null,
    };

    const Compression = struct {
        allocator: Allocator,
        retain_writer: bool,
        write_treshold: usize,
        writer: std.Io.Writer.Allocating,
    };

    pub fn init(io: Io, allocator: Allocator, config: Config) !Client {
        if (config.compression != null) {
            log.err("Compression is disabled as part of the 0.15 upgrade. I do hope to re-enable it soon.", .{});
            return error.InvalidConfiguraion;
        }

        // 0.16: networking via Io.net.HostName
        const host_name = try net.HostName.init(config.host);
        // 0.16: connect requires mode option (stream vs datagram)
        const net_stream = try host_name.connect(io, config.port, .{ .mode = .stream });

        var tls_client: ?*TLSClient = null;
        if (config.tls) {
            tls_client = try TLSClient.init(allocator, io, net_stream, &config);
        }
        const stream = Stream.init(io, net_stream, tls_client);

        var own_bp = false;
        var buffer_provider: *buffer.Provider = undefined;

        // If a buffer_provider is provided, we'll use that.
        // If it isn't, we need to create one which also means we now "own" it
        // and we're responsible for cleaning it up
        if (config.buffer_provider) |shared_bp| {
            buffer_provider = shared_bp;
        } else {
            own_bp = true;
            buffer_provider = try allocator.create(buffer.Provider);
            errdefer allocator.destroy(buffer_provider);
            buffer_provider.* = try buffer.Provider.init(allocator, .{
                .size = 0,
                .count = 0,
                .max = config.max_size,
            });
        }

        errdefer if (own_bp) {
            buffer_provider.deinit();
            allocator.destroy(buffer_provider);
        };

        const reader_buf = try buffer_provider.allocator.alloc(u8, config.buffer_size);
        errdefer buffer_provider.allocator.free(reader_buf);

        return .{
            .io = io,
            .stream = stream,
            ._closed = false,
            ._own_bp = own_bp,
            ._mask_fn = config.mask_fn orelse generateMask,
            ._compression_opts = null, //TODO: ZIG 0.15
            ._reader = Reader.init(reader_buf, buffer_provider, null),
        };
    }

    // 0.16: Alternative init that accepts a pre-existing stream.
    // Supports TLS if config.tls is set (uses config.host for SNI).
    pub fn initWithStream(io: Io, allocator: Allocator, net_stream: net.Stream, config: Config) !Client {
        var tls_client: ?*TLSClient = null;
        if (config.tls) {
            tls_client = try TLSClient.init(allocator, io, net_stream, &config);
        }
        const stream = Stream.init(io, net_stream, tls_client);

        var own_bp = false;
        var buffer_provider: *buffer.Provider = undefined;

        if (config.buffer_provider) |shared_bp| {
            buffer_provider = shared_bp;
        } else {
            own_bp = true;
            buffer_provider = try allocator.create(buffer.Provider);
            errdefer allocator.destroy(buffer_provider);
            buffer_provider.* = try buffer.Provider.init(allocator, .{
                .size = 0,
                .count = 0,
                .max = config.max_size,
            });
        }

        errdefer if (own_bp) {
            buffer_provider.deinit();
            allocator.destroy(buffer_provider);
        };

        const reader_buf = try buffer_provider.allocator.alloc(u8, config.buffer_size);
        errdefer buffer_provider.allocator.free(reader_buf);

        return .{
            .io = io,
            .stream = stream,
            ._closed = false,
            ._own_bp = own_bp,
            ._mask_fn = config.mask_fn orelse generateMask,
            ._compression_opts = null,
            ._reader = Reader.init(reader_buf, buffer_provider, null),
        };
    }

    pub fn deinit(self: *Client) void {
        self.closeStream();

        const larger_buffer_provider = self._reader.large_buffer_provider;
        const allocator = larger_buffer_provider.allocator;
        allocator.free(self._reader.static);

        self._reader.deinit();

        if (self._own_bp) {
            larger_buffer_provider.deinit();
            allocator.destroy(larger_buffer_provider);
        }
    }

    pub fn handshake(self: *Client, path: []const u8, opts: HandshakeOpts) !void {
        const stream = &self.stream;
        errdefer self.closeStream();

        // we've already setup our reader, and the reader has a static buffer
        // we might as well use it!
        const buf = self._reader.static;
        const key = blk: {
            const bin_key = generateKey(self.io);
            var encoded_key: [24]u8 = undefined;
            break :blk std.base64.standard.Encoder.encode(&encoded_key, &bin_key);
        };

        try sendHandshake(path, key, buf, &opts, self._compression_opts != null, stream);

        const res = try HandShakeReply.read(buf, key, &opts, self._compression_opts != null, stream);
        errdefer self.close(.{ .code = 1001 }) catch unreachable;

        // Set up compression with agreed-on parameters
        if (res.compression) {
            try self.setupCompression();
        }

        // We might have read more than handshake response. If so, readHandshakeReply
        // has positioned the extra data at the start of the buffer, but we need
        // to set the length.
        self._reader.pos = res.over_read;
    }

    fn setupCompression(self: *Client) !void {
        std.debug.assert(self._compression_opts != null);
        self._reader.allow_compressed = true;

        const allocator = self._reader.large_buffer_provider.allocator;
        const config = self._compression_opts.?;
        self._compression = .{
            .allocator = allocator,
            .write_treshold = config.write_threshold.?,
            .retain_writer = config.retain_write_buffer,
            .writer = std.Io.Writer.Allocating.init(allocator),
        };
    }

    pub fn readLoop(self: *Client, handler: anytype) !void {
        const Handler = ReadLoopHandler(@TypeOf(handler));
        var reader = &self._reader;

        defer if (comptime std.meta.hasFn(Handler, "close")) {
            handler.close();
        };

        // block until we have data
        try self.readTimeout(0);

        while (true) {
            const message = self.read() catch |err| switch (err) {
                error.Closed => return,
                else => return err,
            } orelse unreachable;

            const message_type = message.type;
            defer reader.done(message_type);

            switch (message_type) {
                .text, .binary => {
                    switch (comptime @typeInfo(@TypeOf(Handler.serverMessage)).@"fn".params.len) {
                        2 => try handler.serverMessage(message.data),
                        3 => try handler.serverMessage(message.data, if (message_type == .text) .text else .binary),
                        else => @compileError(@typeName(Handler) ++ ".serverMessage must accept 2 or 3 parameters"),
                    }
                },
                .ping => if (comptime std.meta.hasFn(Handler, "serverPing")) {
                    try handler.serverPing(message.data);
                } else {
                    // @constCast is safe because we know message.data points to
                    // reader.buffer.buf, which we own and which can be mutated
                    try self.writeFrame(.pong, @constCast(message.data));
                },
                .close => {
                    if (comptime std.meta.hasFn(Handler, "serverClose")) {
                        try handler.serverClose(message.data);
                    } else {
                        self.close(.{}) catch unreachable;
                    }
                    return;
                },
                .pong => if (comptime std.meta.hasFn(Handler, "serverPong")) {
                    try handler.serverPong(message.data);
                },
            }
        }
    }

    pub const HeartbeatConfig = struct {
        /// ping interval in milliseconds. readTimeout is set to this value.
        /// when no data arrives within the interval, a ping is sent.
        interval_ms: u32 = 30_000,
        /// close connection after this many consecutive intervals with no data or pong.
        max_failures: u32 = 4,
    };

    pub fn readLoopWithHeartbeat(self: *Client, handler: anytype, heartbeat: HeartbeatConfig) !void {
        const Handler = ReadLoopHandler(@TypeOf(handler));
        var reader = &self._reader;

        defer if (comptime std.meta.hasFn(Handler, "close")) {
            handler.close();
        };

        try self.readTimeout(heartbeat.interval_ms);

        var pending_pings: u32 = 0;

        while (true) {
            const message = self.read() catch |err| switch (err) {
                error.Closed => return,
                else => return err,
            } orelse {
                // timeout — no data in interval
                pending_pings += 1;
                if (pending_pings >= heartbeat.max_failures) {
                    self.close(.{}) catch {};
                    return error.Closed;
                }
                self.writePing(&.{}) catch {
                    self.close(.{}) catch {};
                    return error.Closed;
                };
                continue;
            };

            // any received frame proves liveness
            pending_pings = 0;

            const message_type = message.type;
            defer reader.done(message_type);

            switch (message_type) {
                .text, .binary => {
                    switch (comptime @typeInfo(@TypeOf(Handler.serverMessage)).@"fn".params.len) {
                        2 => try handler.serverMessage(message.data),
                        3 => try handler.serverMessage(message.data, if (message_type == .text) .text else .binary),
                        else => @compileError(@typeName(Handler) ++ ".serverMessage must accept 2 or 3 parameters"),
                    }
                },
                .ping => if (comptime std.meta.hasFn(Handler, "serverPing")) {
                    try handler.serverPing(message.data);
                } else {
                    try self.writeFrame(.pong, @constCast(message.data));
                },
                .close => {
                    if (comptime std.meta.hasFn(Handler, "serverClose")) {
                        try handler.serverClose(message.data);
                    } else {
                        self.close(.{}) catch unreachable;
                    }
                    return;
                },
                .pong => if (comptime std.meta.hasFn(Handler, "serverPong")) {
                    try handler.serverPong(message.data);
                },
            }
        }
    }

    pub fn read(self: *Client) !?proto.Message {
        var reader = &self._reader;
        const stream = &self.stream;

        while (true) {
            // try to read a message from our buffer first, before trying to
            // get more data from the socket.
            const has_more, const message = reader.read() catch |err| {
                self.close(.{ .code = 1002 }) catch unreachable;
                return err;
            } orelse {
                // 0.16: Io vtable error set changed
                reader.fill(stream) catch |err| {
                    // Check for timeout/would-block type errors
                    if (err == error.Canceled or err == error.WouldBlock) return null;
                    // Check for connection closed errors
                    if (err == error.Closed or err == error.ConnectionResetByPeer or err == error.NotOpenForReading) {
                        @atomicStore(bool, &self._closed, true, .monotonic);
                        return error.Closed;
                    }
                    self.close(.{ .code = 1002 }) catch unreachable;
                    return err;
                };
                continue;
            };

            _ = has_more;
            return message;
        }
    }

    pub fn done(self: *Client, message: proto.Message) void {
        self._reader.done(message.type);
    }

    pub fn readLoopInNewThread(self: *Client, h: anytype) !std.Thread {
        return std.Thread.spawn(.{}, readLoopOwnedThread, .{ self, h });
    }

    fn readLoopOwnedThread(self: *Client, h: anytype) void {
        self.readLoop(h) catch {};
    }

    pub fn writeTimeout(self: *const Client, ms: u32) !void {
        return self.stream.writeTimeout(ms);
    }

    pub fn readTimeout(self: *const Client, ms: u32) !void {
        return self.stream.readTimeout(ms);
    }

    pub fn write(self: *Client, data: []u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn writeText(self: *Client, data: []u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn writeBin(self: *Client, data: []u8) !void {
        return self.writeFrame(.binary, data);
    }

    pub fn writePing(self: *Client, data: []u8) !void {
        return self.writeFrame(.ping, data);
    }

    pub fn writePong(self: *Client, data: []u8) !void {
        return self.writeFrame(.pong, data);
    }

    const CloseOpts = struct {
        code: ?u16 = null,
        reason: []const u8 = "",
    };

    pub fn close(self: *Client, opts: CloseOpts) !void {
        if (@atomicRmw(bool, &self._closed, .Xchg, true, .monotonic) == true) {
            // already closed
            return;
        }

        defer self.stream.close();

        const code = opts.code orelse {
            self.writeFrame(.close, "") catch {};
            return;
        };

        const reason = opts.reason;
        if (reason.len > 123) {
            return error.ReasonTooLong;
        }

        var buf: [125]u8 = undefined;
        buf[0] = @intCast((code >> 8) & 0xFF);
        buf[1] = @intCast(code & 0xFF);

        const end = 2 + reason.len;
        @memcpy(buf[2..end], reason);
        self.writeFrame(.close, buf[0..end]) catch {};
    }

    pub fn writeFrame(self: *Client, op_code: proto.OpCode, data: []u8) !void {
        const payload = data;
        const compressed = false;

        // maximum possible prefix length. op_code + length_type + 8byte length + 4 byte mask
        var buf: [14]u8 = undefined;
        const header = proto.writeFrameHeader(&buf, op_code, payload.len, compressed);

        const header_len = header.len;
        const header_end = header.len + 4; // for the mask

        buf[1] |= 128; // indicate that the payload is masked

        const mask = self._mask_fn(self.io);
        @memcpy(buf[header_len..header_end], &mask);

        if (payload.len > 0) {
            proto.mask(&mask, payload);
        }

        // Serialize writes — concurrent ping/pong/close must not interleave frames.
        self._write_lock.lockUncancelable(self.io);
        defer self._write_lock.unlock(self.io);

        try self.stream.writeAll(buf[0..header_end]);
        if (payload.len > 0) {
            try self.stream.writeAll(payload);
        }
    }

    pub fn isClosed(self: *const Client) bool {
        return @atomicLoad(bool, &self._closed, .monotonic);
    }

    fn closeStream(self: *Client) void {
        if (@atomicRmw(bool, &self._closed, .Xchg, true, .monotonic) == false) {
            self.stream.close();
        }
    }
};

// wraps a net.Stream and optional a tls.Client
pub const Stream = struct {
    io: Io,
    stream: net.Stream,
    tls_client: ?*TLSClient = null,

    pub fn init(io: Io, stream: net.Stream, tls_client: ?*TLSClient) Stream {
        return .{
            .io = io,
            .stream = stream,
            .tls_client = tls_client,
        };
    }

    pub fn close(self: *Stream) void {
        if (self.tls_client) |tls_client| {
            self.stream.shutdown(self.io, .both) catch {};
            tls_client.deinit();
        }
        self.stream.close(self.io);
    }

    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.tls_client) |tls_client| {
            var w: std.Io.Writer = .fixed(buf);
            while (true) {
                const n = try tls_client.client.reader.stream(&w, .limited(buf.len));
                if (n != 0) {
                    return n;
                }
            }
        }
        var bufs = [_][]u8{buf};
        return self.io.vtable.netRead(self.io.userdata, self.stream.socket.handle, &bufs) catch |err| {
            return switch (err) {
                error.ConnectionResetByPeer => error.ConnectionResetByPeer,
                error.Timeout => error.WouldBlock,
                else => error.Unexpected,
            };
        };
    }

    pub fn writeAll(self: *Stream, data: []const u8) !void {
        if (self.tls_client) |tls_client| {
            try tls_client.client.writer.writeAll(data);
            try tls_client.client.writer.flush();
            try tls_client.stream_writer.interface.flush();
            return;
        }
        var remaining = data;
        while (remaining.len > 0) {
            // netWrite: header is sent first, data array's last element is the splat pattern.
            // Pass remaining as header, empty pattern with splat=0.
            const empty = [_][]const u8{""};
            const n = self.io.vtable.netWrite(self.io.userdata, self.stream.socket.handle, remaining, &empty, 0) catch |err| {
                return switch (err) {
                    error.ConnectionResetByPeer => error.ConnectionResetByPeer,
                    else => error.Unexpected,
                };
            };
            if (n == 0) return error.Unexpected;
            remaining = remaining[n..];
        }
    }

    const zero_timeout = std.mem.toBytes(posix.timeval{ .sec = 0, .usec = 0 });
    pub fn writeTimeout(self: *const Stream, ms: u32) !void {
        return self.setTimeout(posix.SO.SNDTIMEO, ms);
    }

    pub fn readTimeout(self: *const Stream, ms: u32) !void {
        return self.setTimeout(posix.SO.RCVTIMEO, ms);
    }

    fn setTimeout(self: *const Stream, opt_name: u32, ms: u32) !void {
        if (ms == 0) {
            return self.setsockopt(opt_name, &zero_timeout);
        }

        const timeout = std.mem.toBytes(posix.timeval{
            .sec = @intCast(@divTrunc(ms, 1000)),
            .usec = @intCast(@mod(ms, 1000) * 1000),
        });
        return self.setsockopt(opt_name, &timeout);
    }

    pub fn setsockopt(self: *const Stream, opt_name: u32, value: []const u8) !void {
        return posix.setsockopt(self.stream.socket.handle, posix.SOL.SOCKET, opt_name, value);
    }
};

const TLSClient = struct {
    client: tls.Client,
    stream: net.Stream,
    stream_writer: net.Stream.Writer,
    stream_reader: net.Stream.Reader,
    arena: std.heap.ArenaAllocator,

    fn init(allocator: Allocator, io: Io, stream: net.Stream, config: *const Client.Config) !*TLSClient {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const aa = arena.allocator();

        const bundle_ptr = try aa.create(Bundle);
        if (config.ca_bundle) |ca| {
            bundle_ptr.* = ca;
        } else {
            bundle_ptr.* = .{ .map = .empty, .bytes = .empty };
            try bundle_ptr.rescan(aa, io, Io.Timestamp.zero);
        }

        const rwlock = try aa.create(std.Io.RwLock);
        rwlock.* = std.Io.RwLock.init;

        // The TLS input and output have to be max_ciphertext_record_len each.
        // It isn't clear to me how big the un-encrypted reader and writer
        // need to be. I would think 0, but that will fail an assertion. I
        // don't think that it's right that we need 4 buffers, but apparently
        // we do. Until i figure this out, using 4 x max_ciphertext_record_len
        // seems like the only safe choice.
        const buf_len = std.crypto.tls.max_ciphertext_record_len;
        var buf = try aa.alloc(u8, buf_len * 4);

        const self = try aa.create(TLSClient);
        self.* = .{
            .stream = stream,
            .arena = arena,
            .client = undefined,
            .stream_writer = stream.writer(io, buf.ptr[0..buf_len][0..buf_len]),
            .stream_reader = stream.reader(io, buf.ptr[buf_len .. 2 * buf_len][0..buf_len]),
        };

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        self.client = try tls.Client.init(
            &self.stream_reader.interface,
            &self.stream_writer.interface,
            .{
                .ca = .{ .bundle = .{ .gpa = aa, .io = io, .lock = rwlock, .bundle = bundle_ptr } },
                .host = .{ .explicit = config.host },
                .read_buffer = buf.ptr[2 * buf_len .. 3 * buf_len][0..buf_len],
                .write_buffer = buf.ptr[3 * buf_len .. 4 * buf_len][0..buf_len],
                .entropy = &entropy,
                .realtime_now = Io.Timestamp.now(io, .real),
            },
        );

        return self;
    }

    fn deinit(self: *TLSClient) void {
        _ = self.client.end() catch {};
        self.arena.deinit();
    }
};

fn generateKey(io: Io) [16]u8 {
    if (comptime @import("builtin").is_test) {
        return [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    }
    // 0.16: io.random() fills a buffer
    var key: [16]u8 = undefined;
    io.random(&key);
    return key;
}

fn generateMask(io: Io) [4]u8 {
    // 0.16: io.random() fills a buffer
    var mask: [4]u8 = undefined;
    io.random(&mask);
    return mask;
}

fn sendHandshake(path: []const u8, key: []const u8, buf: []u8, opts: *const Client.HandshakeOpts, compression: bool, stream: anytype) !void {
    @memcpy(buf[0..4], "GET ");
    var pos: usize = 4;
    var end = pos + path.len;

    {
        @memcpy(buf[pos..end], path);
        pos = end;
    }

    {
        const headers = " HTTP/1.1\r\ncontent-length: 0\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nconnection: upgrade\r\nsec-websocket-key: ";
        end = pos + headers.len;
        @memcpy(buf[pos..end], headers);

        pos = end;
        end = pos + key.len;
        @memcpy(buf[pos..end], key);
    }

    if (compression) {
        // NOTE: client_max_window_bits is unsupported
        const permessage_deflate = "\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover";
        pos = end;
        end = pos + permessage_deflate.len;
        @memcpy(buf[pos..end], permessage_deflate);
    }

    {
        pos = end;
        end = pos + 2;
        @memcpy(buf[pos..end], "\r\n");
        pos = end;
    }

    if (opts.headers) |extra_headers| {
        end = pos + extra_headers.len;
        @memcpy(buf[pos..end], extra_headers);
        pos = end;
        if (!std.mem.endsWith(u8, extra_headers, "\r\n")) {
            buf[pos] = '\r';
            buf[pos + 1] = '\n';
            pos += 2;
        }
    }
    buf[pos] = '\r';
    buf[pos + 1] = '\n';

    try stream.writeTimeout(opts.timeout_ms);
    try stream.writeAll(buf[0 .. pos + 2]);
    try stream.writeTimeout(0);
}

const HandShakeReply = struct {
    compression: bool,
    over_read: usize,

    fn read(buf: []u8, key: []const u8, opts: *const Client.HandshakeOpts, compression: bool, stream: anytype) !HandShakeReply {
        const timeout_ms = opts.timeout_ms;
        const deadline = milliTimestamp(stream.io) + timeout_ms;
        try stream.readTimeout(timeout_ms);

        var pos: usize = 0;
        var line_start: usize = 0;
        var complete_response: u8 = 0;
        var server_compression: bool = false;

        while (true) {
            // 0.16: using libc recv, WouldBlock indicates timeout
            const n = stream.read(buf[pos..]) catch |err| switch (err) {
                error.WouldBlock => return error.Timeout,
                else => return err,
            };
            if (n == 0) {
                return error.ConnectionClosed;
            }

            pos += n;
            while (std.mem.indexOfScalar(u8, buf[line_start..pos], '\r')) |relative_end| {
                if (relative_end == 0) {
                    if (complete_response != 15) {
                        return error.InvalidHandshakeResponse;
                    }
                    const over_read = pos - (line_start + 2);
                    std.mem.copyForwards(u8, buf[0..over_read], buf[line_start + 2 .. pos]);
                    try stream.readTimeout(0);
                    return .{
                        .over_read = over_read,
                        .compression = server_compression,
                    };
                }

                const line_end = line_start + relative_end;
                const line = buf[line_start..line_end];

                // the next line starts where this line ends, skip over the \r\n.
                // TCP can split mid-CRLF — if \n hasn't arrived yet, break to
                // the outer read loop for more data.
                line_start = line_end + 2;
                if (line_start > pos) break;

                if (complete_response == 0) {
                    if (!ascii.startsWithIgnoreCase(line, "HTTP/1.1 101 ")) {
                        return error.InvalidHandshakeResponse;
                    }
                    complete_response |= 1;
                    continue;
                }

                for (line, 0..) |b, i| {
                    // find the colon and lowercase the header while we're iterating
                    if ('A' <= b and b <= 'Z') {
                        line[i] = b + 32;
                        continue;
                    }

                    if (b != ':') {
                        continue;
                    }

                    switch (i) {
                        7 => if (std.mem.eql(u8, line[0..i], "upgrade")) {
                            if (!ascii.eqlIgnoreCase(std.mem.trim(u8, line[i + 1 ..], &ascii.whitespace), "websocket")) {
                                return error.InvalidUpgradeHeader;
                            }
                            complete_response |= 2;
                        },
                        10 => if (std.mem.eql(u8, line[0..i], "connection")) {
                            if (!ascii.eqlIgnoreCase(std.mem.trim(u8, line[i + 1 ..], &ascii.whitespace), "upgrade")) {
                                return error.InvalidConnectionHeader;
                            }
                            complete_response |= 4;
                        },
                        20 => if (std.mem.eql(u8, line[0..i], "sec-websocket-accept")) {
                            var h: [20]u8 = undefined;
                            {
                                var hasher = std.crypto.hash.Sha1.init(.{});
                                hasher.update(key);
                                hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                                hasher.final(&h);
                            }

                            var encoded_buf: [28]u8 = undefined;
                            const sec_hash = std.base64.standard.Encoder.encode(&encoded_buf, &h);
                            const header_value = std.mem.trim(u8, line[i + 1 ..], &ascii.whitespace);

                            if (!std.mem.eql(u8, header_value, sec_hash)) {
                                return error.InvalidWebsocketAcceptHeader;
                            }
                            complete_response |= 8;
                        },
                        24 => if (std.mem.eql(u8, line[0..i], "sec-websocket-extensions")) {
                            if (try parseExtension(line[i + 1 ..])) |sc| {
                                if (!compression) {
                                    // server is saying compression, but we didn't ask for it.
                                    return error.InvalidExtensionHeader;
                                }
                                if (!sc.client_no_context_takeover or !sc.server_no_context_takeover) {
                                    // as of Zig 0.15, we no longer support context takeover
                                    // We told the server this, it should have respected it.
                                    return error.InvalidExtensionHeader;
                                }

                                server_compression = true;
                            }
                        },
                        else => {}, // some other header we don't care about
                    }
                }
            }

            if (milliTimestamp(stream.io) > deadline) {
                return error.Timeout;
            }

            if (pos == buf.len) {
                return error.ResponseTooLarge;
            }
        }
    }

    pub fn parseExtension(value: []const u8) !?ServerHandshake.Compression {
        var deflate = false;
        var client_max_bits: u8 = 15;
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
            const client_max_window_bits = "client_max_window_bits=";
            if (std.mem.startsWith(u8, param, client_max_window_bits)) {
                client_max_bits = std.fmt.parseInt(u8, param[client_max_window_bits.len..], 10) catch {
                    return error.InvalidCompressionServerMaxBits;
                };
            }
        }
        if (deflate == false) {
            return null;
        }

        if (client_max_bits != 15) {
            // We don't offer client window, so if the server asks for one, that's an error
            return error.InvalidExtensionHeader;
        }

        return .{
            .client_no_context_takeover = client_no_context_takeover,
            .server_no_context_takeover = server_no_context_takeover,
        };
    }
};

const t = @import("../t.zig");
test "Client: handshake" {
    {
        // empty response
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidHandshakeResponse, client.handshake("/", .{}));
    }

    {
        // invalid websocket response
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 200 OK\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidHandshakeResponse, client.handshake("/", .{}));
    }

    {
        // missing upgrade header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidHandshakeResponse, client.handshake("/", .{}));
    }

    {
        // wrong upgrade header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nUpgrade: nope\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidUpgradeHeader, client.handshake("/", .{}));
    }

    {
        // missing connection header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidHandshakeResponse, client.handshake("/", .{}));
    }

    {
        // wrong connection header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nupgrade: WebSocket\r\nConnection: something\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidConnectionHeader, client.handshake("/", .{}));
    }

    {
        // missing Sec-Websocket-Accept header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidHandshakeResponse, client.handshake("/", .{}));
    }

    {
        // wrong Sec-Websocket-Accept header
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nupgrade: WebSocket\r\nConnection: UPGRADE\r\nSec-Websocket-Accept: hack\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try t.expectError(error.InvalidWebsocketAcceptHeader, client.handshake("/", .{}));
    }

    {
        // ok for successful
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nupgrade: WebSocket\r\nConnection: UPGRADE\r\nSec-Websocket-Accept: C/0nmHhBztSRGR1CwL6Tf4ZjwpY=\r\n\r\n");

        var client = testClient(&pair);
        defer client.deinit();
        try client.handshake("/", .{});
        try t.expectEqual(0, client._reader.pos);
    }

    {
        // ok for successful, with overread
        var pair = t.SocketPair.init(.{});
        defer pair.deinit();
        try pair.clientWriteAll("HTTP/1.1 101 Switching Protocol\r\nupgrade: WebSocket\r\nConnection: UPGRADE\r\nSec-Websocket-Accept: C/0nmHhBztSRGR1CwL6Tf4ZjwpY=\r\n\r\nSome Random Data Which is Part Of the Next Message");

        var client = testClient(&pair);
        defer client.deinit();
        try client.handshake("/", .{});
        try t.expectEqual(50, client._reader.pos);
    }
}

test "Client: write/read" {
    const io = std.Options.debug_io;
    const stream = try testConnectedStream(io, "127.0.0.1", 9292);
    var client = try Client.initWithStream(io, t.allocator, stream, .{
        .port = 9292,
        .host = "127.0.0.1",
    });
    defer client.deinit();

    try client.handshake("/", .{
        .timeout_ms = 1000,
    });

    var buf = [_]u8{ 'o', 'v', 'e', 'r' };
    try client.write(&buf);
    try client.readTimeout(1000);

    const message = (try client.read()) orelse unreachable;
    try t.expectEqual(.text, message.type);
    try t.expectString("9000", message.data);

    client.close(.{}) catch unreachable;
}

test "Client: close with code" {
    const io = std.Options.debug_io;
    const stream = try testConnectedStream(io, "127.0.0.1", 9292);
    var client = try Client.initWithStream(io, t.allocator, stream, .{
        .port = 9292,
        .host = "127.0.0.1",
    });
    defer client.deinit();

    try client.handshake("/", .{
        .timeout_ms = 1000,
    });

    client.close(.{ .code = 4002 }) catch unreachable;
}

test "Client: with code and reason" {
    const io = std.Options.debug_io;
    const stream = try testConnectedStream(io, "127.0.0.1", 9292);
    var client = try Client.initWithStream(io, t.allocator, stream, .{
        .port = 9292,
        .host = "127.0.0.1",
    });
    defer client.deinit();

    try client.handshake("/", .{
        .timeout_ms = 1000,
    });

    client.close(.{ .code = 4002, .reason = "goodbye" }) catch unreachable;
}

test "Client: Handler" {
    var h = try ClientHandler.init(t.allocator);
    defer h.deinit();

    var buf: [6]u8 = undefined;
    {
        @memcpy(buf[0..3], "dyn");
        try h.client.write(buf[0..3]);
    }

    {
        @memcpy(buf[0..4], "ping");
        try h.client.write(buf[0..4]);
    }

    {
        @memcpy(buf[0..4], "pong");
        try h.client.write(buf[0..4]);
    }

    {
        @memcpy(buf[0..6], "close1");
        try h.client.write(buf[0..6]);
    }

    try h.client.readLoop(&h);

    // if pong is true then ping and message have to be true
    // because each asserts the previous
    try t.expectEqual(true, h.pong);
    try t.expectEqual(true, h.closed);
}

fn testClient(pair: *t.SocketPair) Client {
    pair.server_taken = true;
    const stream = pair.server;
    const io = std.Options.debug_io;
    const bp = t.allocator.create(buffer.Provider) catch unreachable;
    bp.* = buffer.Provider.init(t.allocator, .{ .count = 0, .size = 0, .max = 4096 }) catch unreachable;

    const reader_buf = bp.allocator.alloc(u8, 1024) catch unreachable;

    return .{
        .io = io,
        ._closed = false,
        ._own_bp = true,
        ._mask_fn = generateMask,
        ._compression_opts = null,
        .stream = .{ .io = io, .stream = stream },
        ._reader = Reader.init(reader_buf, bp, null),
    };
}

fn testConnectedStream(io: Io, host: []const u8, port: u16) !net.Stream {
    const addr = try net.IpAddress.parse(host, port);
    return net.IpAddress.connect(&addr, io, .{ .mode = .stream });
}

const ClientHandler = struct {
    ping: bool = false,
    pong: bool = false,
    closed: bool = false,
    message: bool = false,
    client: Client,

    fn init(allocator: Allocator) !ClientHandler {
        const io = std.Options.debug_io;
        const stream = try testConnectedStream(io, "127.0.0.1", 9292);
        var client = try Client.initWithStream(io, allocator, stream, .{
            .port = 9292,
            .host = "127.0.0.1",
        });
        errdefer client.deinit();

        try client.handshake("/", .{
            .timeout_ms = 1000,
        });

        return .{
            .client = client,
        };
    }

    fn deinit(self: *ClientHandler) void {
        self.client.deinit();
    }

    pub fn serverMessage(self: *ClientHandler, data: []u8, tpe: proto.Message.TextType) !void {
        try t.expectEqual(.text, tpe);
        try t.expectString("over 9000!", data);
        self.message = true;
    }

    pub fn serverPing(self: *ClientHandler, data: []u8) !void {
        try t.expectEqual(true, self.message);
        try t.expectString("a-ping", data);
        self.ping = true;
    }

    pub fn serverPong(self: *ClientHandler, data: []u8) !void {
        try t.expectEqual(true, self.ping);
        try t.expectString("a-pong", data);
        self.pong = true;
    }

    pub fn close(self: *ClientHandler) void {
        self.client.close(.{}) catch unreachable;
        self.closed = true;
    }
};
