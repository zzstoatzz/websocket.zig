const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const websocket_module = b.addModule("websocket", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/websocket.zig"),
    });

    {
        const options = b.addOptions();
        options.addOption(bool, "websocket_blocking", false);
        websocket_module.addOptions("build", options);
    }

    {
        // run tests
        const force_blocking = b.option(bool, "force_blocking", "Force blocking mode") orelse false;
        const options = b.addOptions();
        options.addOption(bool, "websocket_blocking", force_blocking);

        const test_module = b.createModule(.{
            .root_source_file = b.path("src/websocket.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_module.addOptions("build", options);

        const tests = b.addTest(.{
            .root_module = test_module,
            .test_runner = .{ .path = b.path("test_runner.zig"), .mode = .simple },
        });

        const run_test = b.addRunArtifact(tests);

        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&run_test.step);
    }
}
