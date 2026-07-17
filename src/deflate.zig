const std = @import("std");

const c = @cImport({
    @cInclude("zlib.h");
});

const Allocator = std.mem.Allocator;

pub const Error = error{
    CompressionInitFailed,
    CompressionFailed,
    CompressionResetFailed,
    DecompressionInitFailed,
    DecompressionFailed,
    DecompressionResetFailed,
    InvalidCompressionTail,
};

pub const Compressor = struct {
    stream: c.z_stream,

    pub fn init(self: *Compressor) Error!void {
        self.stream = std.mem.zeroes(c.z_stream);
        if (c.deflateInit2(
            &self.stream,
            c.Z_DEFAULT_COMPRESSION,
            c.Z_DEFLATED,
            -c.MAX_WBITS,
            8,
            c.Z_DEFAULT_STRATEGY,
        ) != c.Z_OK) return error.CompressionInitFailed;
    }

    pub fn deinit(self: *Compressor) void {
        _ = c.deflateEnd(&self.stream);
    }

    pub fn reset(self: *Compressor) Error!void {
        if (c.deflateReset(&self.stream) != c.Z_OK)
            return error.CompressionResetFailed;
    }

    pub fn compress(
        self: *Compressor,
        allocator: Allocator,
        input: []const u8,
        output: *std.ArrayList(u8),
    ) (Allocator.Error || Error)![]const u8 {
        output.clearRetainingCapacity();
        var input_offset: usize = 0;
        while (true) {
            if (self.stream.avail_in == 0 and input_offset < input.len) {
                const n = @min(input.len - input_offset, std.math.maxInt(c.uInt));
                self.stream.next_in = @constCast(input[input_offset..].ptr);
                self.stream.avail_in = @intCast(n);
                input_offset += n;
            }

            try output.ensureUnusedCapacity(allocator, 16 * 1024);
            const writable = output.unusedCapacitySlice();
            const capacity = @min(writable.len, std.math.maxInt(c.uInt));
            self.stream.next_out = writable.ptr;
            self.stream.avail_out = @intCast(capacity);
            const flush: c_int = if (input_offset == input.len) c.Z_SYNC_FLUSH else c.Z_NO_FLUSH;
            const result = c.deflate(&self.stream, flush);
            if (result != c.Z_OK) return error.CompressionFailed;
            const written = capacity - self.stream.avail_out;
            output.items.len += written;

            if (flush == c.Z_SYNC_FLUSH and self.stream.avail_in == 0 and self.stream.avail_out != 0)
                break;
        }

        const tail = "\x00\x00\xff\xff";
        if (output.items.len < tail.len or
            !std.mem.eql(u8, output.items[output.items.len - tail.len ..], tail))
            return error.InvalidCompressionTail;
        output.items.len -= tail.len;
        return output.items;
    }
};

pub const Decompressor = struct {
    stream: c.z_stream,

    pub fn init(self: *Decompressor) Error!void {
        self.stream = std.mem.zeroes(c.z_stream);
        if (c.inflateInit2(&self.stream, -c.MAX_WBITS) != c.Z_OK)
            return error.DecompressionInitFailed;
    }

    pub fn deinit(self: *Decompressor) void {
        _ = c.inflateEnd(&self.stream);
    }

    pub fn reset(self: *Decompressor) Error!void {
        if (c.inflateReset(&self.stream) != c.Z_OK)
            return error.DecompressionResetFailed;
    }

    pub fn decompress(self: *Decompressor, input: []const u8, output: anytype) Error!void {
        var input_offset: usize = 0;
        var chunk: [16 * 1024]u8 = undefined;
        while (true) {
            if (self.stream.avail_in == 0 and input_offset < input.len) {
                const n = @min(input.len - input_offset, std.math.maxInt(c.uInt));
                self.stream.next_in = @constCast(input[input_offset..].ptr);
                self.stream.avail_in = @intCast(n);
                input_offset += n;
            }
            self.stream.next_out = &chunk;
            self.stream.avail_out = chunk.len;
            const result = c.inflate(&self.stream, c.Z_SYNC_FLUSH);
            if (result != c.Z_OK and result != c.Z_BUF_ERROR)
                return error.DecompressionFailed;
            const written = chunk.len - self.stream.avail_out;
            output.writeAll(chunk[0..written]) catch return error.DecompressionFailed;

            if (input_offset == input.len and self.stream.avail_in == 0 and self.stream.avail_out != 0)
                break;
            if (written == 0 and self.stream.avail_in == 0 and input_offset == input.len)
                return error.DecompressionFailed;
        }
    }
};
