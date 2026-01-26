const std = @import("std");
const proto = @import("proto.zig");

const c = std.c;
const Io = std.Io;
const posix = std.posix;
const ArrayList = std.ArrayList;

const Message = proto.Message;

pub const allocator = std.testing.allocator;

// 0.16: expectEqual argument order changed (expected, actual)
pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected, actual);
}

pub const expectError = std.testing.expectError;
pub const expectString = std.testing.expectEqualStrings;
pub const expectSlice = std.testing.expectEqualSlices;

// 0.16: posix.getrandom removed, use io.random() which fills a buffer
pub fn getRandom() std.Random.DefaultPrng {
    const io = std.Options.debug_io;
    var seed_bytes: [8]u8 = undefined;
    io.random(&seed_bytes);
    const seed: u64 = @bitCast(seed_bytes);
    return std.Random.DefaultPrng.init(seed);
}

pub var arena = std.heap.ArenaAllocator.init(allocator);
pub fn reset() void {
    _ = arena.reset(.free_all);
}

pub const Writer = struct {
    pos: usize,
    buf: std.ArrayList(u8),
    random: std.Random.DefaultPrng,

    pub fn init() Writer {
        return .{
            .pos = 0,
            .buf = .empty,
            .random = getRandom(),
        };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(allocator);
    }

    pub fn ping(self: *Writer) void {
        return self.pingPayload("");
    }

    pub fn pong(self: *Writer) void {
        return self.frame(true, 10, "", 0);
    }

    pub fn pingPayload(self: *Writer, payload: []const u8) void {
        return self.frame(true, 9, payload, 0);
    }

    pub fn textFrame(self: *Writer, fin: bool, payload: []const u8) void {
        return self.frame(fin, 1, payload, 0);
    }

    pub fn cont(self: *Writer, fin: bool, payload: []const u8) void {
        return self.frame(fin, 0, payload, 0);
    }

    pub fn frame(self: *Writer, fin: bool, op_code: u8, payload: []const u8, reserved: u8) void {
        var buf = &self.buf;

        const l = payload.len;
        var length_of_length: usize = 0;

        if (l > 125) {
            if (l < 65536) {
                length_of_length = 2;
            } else {
                length_of_length = 8;
            }
        }

        // 2 byte header + length_of_length + mask + payload_length
        const needed = 2 + length_of_length + 4 + l;
        buf.ensureUnusedCapacity(allocator, needed) catch unreachable;

        if (fin) {
            buf.appendAssumeCapacity(128 | op_code | reserved);
        } else {
            buf.appendAssumeCapacity(op_code | reserved);
        }

        if (length_of_length == 0) {
            buf.appendAssumeCapacity(128 | @as(u8, @intCast(l)));
        } else if (length_of_length == 2) {
            buf.appendAssumeCapacity(128 | 126);
            buf.appendAssumeCapacity(@intCast((l >> 8) & 0xFF));
            buf.appendAssumeCapacity(@intCast(l & 0xFF));
        } else {
            buf.appendAssumeCapacity(128 | 127);
            buf.appendAssumeCapacity(@intCast((l >> 56) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 48) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 40) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 32) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 24) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 16) & 0xFF));
            buf.appendAssumeCapacity(@intCast((l >> 8) & 0xFF));
            buf.appendAssumeCapacity(@intCast(l & 0xFF));
        }

        var mask: [4]u8 = undefined;
        self.random.random().bytes(&mask);
        // var mask = [_]u8{1, 1, 1, 1};

        buf.appendSliceAssumeCapacity(&mask);
        for (payload, 0..) |b, i| {
            buf.appendAssumeCapacity(b ^ mask[i & 3]);
        }
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn clear(self: *Writer) void {
        self.pos = 0;
        self.buf.clearRetainingCapacity();
    }

    pub fn read(
        self: *Writer,
        buf: []u8,
    ) !usize {
        const data = self.buf.items[self.pos..];

        if (data.len == 0 or buf.len == 0) {
            return 0;
        }

        // randomly fragment the data
        const to_read = self.random.random().intRangeAtMost(usize, 1, @min(data.len, buf.len));
        @memcpy(buf[0..to_read], data[0..to_read]);
        self.pos += to_read;
        return to_read;
    }
};

// 0.16: Io.net.Stream doesn't have read method, use libc.recv wrapper
pub const StreamReader = struct {
    socket: posix.socket_t,

    pub fn read(self: *StreamReader, buf: []u8) !usize {
        const rc = c.recv(self.socket, buf.ptr, buf.len, 0);
        if (rc == -1) {
            const err = posix.errno(-1);
            return switch (err) {
                .CONNRESET => error.ConnectionResetByPeer,
                .AGAIN => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        return @intCast(rc);
    }
};

// 0.16: sockaddr_in not in std.c, define locally for darwin
const SockaddrIn = extern struct {
    len: u8 = @sizeOf(SockaddrIn),
    family: u8 = c.AF.INET,
    port: u16,
    addr: u32,
    zero: [8]u8 = [_]u8{0} ** 8,
};

pub const SocketPair = struct {
    writer: Writer,
    io: Io,
    client: Io.net.Stream,
    server: Io.net.Stream,

    const Opts = struct {
        port: ?u16 = null,
    };

    pub fn init(opts: Opts) SocketPair {
        const io = std.Options.debug_io;
        const port: u16 = opts.port orelse 0;

        // 0.16: use libc directly for socket operations
        // Note: SOCK.CLOEXEC is not supported by darwin, set CLOEXEC via fcntl
        const listener = c.socket(c.AF.INET, c.SOCK.STREAM, c.IPPROTO.TCP);
        if (listener == -1) unreachable;
        _ = c.fcntl(listener, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
        defer _ = c.close(listener);

        // setup sockaddr_in for 127.0.0.1
        var addr: SockaddrIn = .{
            .port = @byteSwap(port),
            .addr = 0x0100007f, // 127.0.0.1 in network byte order
        };

        {
            // setup our listener
            if (c.bind(listener, @ptrCast(&addr), @sizeOf(SockaddrIn)) == -1) unreachable;
            if (c.listen(listener, 1) == -1) unreachable;
            // get assigned port
            var addr_len: c.socklen_t = @sizeOf(SockaddrIn);
            if (c.getsockname(listener, @ptrCast(&addr), &addr_len) == -1) unreachable;
        }

        const client_fd = c.socket(c.AF.INET, c.SOCK.STREAM, c.IPPROTO.TCP);
        if (client_fd == -1) unreachable;
        {
            // connect the client
            const flags = c.fcntl(client_fd, c.F.GETFL);
            _ = c.fcntl(client_fd, c.F.SETFL, flags | @as(c_int, c.SOCK.NONBLOCK));
            const connect_result = c.connect(client_fd, @ptrCast(&addr), @sizeOf(SockaddrIn));
            if (connect_result == -1) {
                const err = std.posix.errno(connect_result);
                if (err != .INPROGRESS) unreachable;
            }
            _ = c.fcntl(client_fd, c.F.SETFL, flags);
        }

        var client_addr: c.sockaddr = undefined;
        var client_addr_len: c.socklen_t = @sizeOf(c.sockaddr);
        const server_fd = c.accept(listener, &client_addr, &client_addr_len);
        if (server_fd == -1) unreachable;

        // 0.16: Socket struct requires address field
        const loopback = Io.net.Ip4Address.loopback(@byteSwap(addr.port));
        return .{
            .io = io,
            .client = .{ .socket = .{ .handle = client_fd, .address = .{ .ip4 = loopback } } },
            .server = .{ .socket = .{ .handle = server_fd, .address = .{ .ip4 = loopback } } },
            .writer = Writer.init(),
        };
    }

    pub fn deinit(self: *SocketPair) void {
        self.writer.deinit();
        // 0.16: use libc.close directly
        _ = c.close(self.client.socket.handle);
        _ = c.close(self.server.socket.handle);
    }

    pub fn pingPayload(self: *SocketPair, payload: []const u8) void {
        self.writer.pingPayload(payload);
    }

    pub fn textFrame(self: *SocketPair, fin: bool, payload: []const u8) void {
        self.writer.textFrame(fin, payload);
    }

    pub fn cont(self: *SocketPair, fin: bool, payload: []const u8) void {
        self.writer.cont(fin, payload);
    }

    pub fn sendBuf(self: *SocketPair) void {
        // 0.16: use libc.send directly (debug_io doesn't support real network)
        const data = self.writer.bytes();
        var remaining = data;
        while (remaining.len > 0) {
            const rc = c.send(self.client.socket.handle, remaining.ptr, remaining.len, 0);
            if (rc <= 0) unreachable;
            const n: usize = @intCast(rc);
            remaining = remaining[n..];
        }
        self.writer.clear();
    }

    // 0.16: use libc.send directly
    pub fn clientWriteAll(self: *SocketPair, data: []const u8) !void {
        var remaining = data;
        while (remaining.len > 0) {
            const rc = c.send(self.client.socket.handle, remaining.ptr, remaining.len, 0);
            if (rc <= 0) return error.SendError;
            const n: usize = @intCast(rc);
            remaining = remaining[n..];
        }
    }

    // 0.16: return StreamReader wrapper for server socket
    pub fn serverReader(self: *SocketPair) StreamReader {
        return .{ .socket = self.server.socket.handle };
    }

    // 0.16: return StreamReader wrapper for client socket
    pub fn clientReader(self: *SocketPair) StreamReader {
        return .{ .socket = self.client.socket.handle };
    }
};
