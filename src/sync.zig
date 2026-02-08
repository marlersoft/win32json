pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    const all_args = try std.process.argsAlloc(allocator);
    // don't care about freeing args

    const cmd_args = all_args[1..];
    if (cmd_args.len != 1) {
        std.log.err("expected 1 cmdline argument but got {}", .{cmd_args.len});
        std.process.exit(0xff);
    }
    const generate_sha_file_path = cmd_args[0];
    // const gen_repo = cmd_args[0];
    // const main_sha_file_path = cmd_args[1];
    // const releases_file_path = cmd_args[2];
    // const zigwin32_repo = cmd_args[3];
    // const clean_arg = cmd_args[4];

    // const do_clean = if (std.mem.eql(u8, clean_arg, "noclean"))
    //     false
    // else if (std.mem.eql(u8, clean_arg, "clean"))
    //     true
    // else
    //     fatal("unexpected clean cmdline argument '{s}'", .{clean_arg});

    const generate_sha = switch (try common.readSha(generate_sha_file_path)) {
        .invalid => |reason| errExit("read sha from '{s}' failed: {s}", .{ generate_sha_file_path, reason }),
        .good => |sha| sha,
    };
    std.log.info("generate branch sha: {s}", .{&generate_sha});
    @panic("todo");
}

const errExit = common.errExit;

const std = @import("std");
const common = @import("common.zig");
