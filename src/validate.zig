const std = @import("std");

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();
    const all_args = try std.process.argsAlloc(arena);
    if (all_args.len != 2) @panic("unexpected number of cmdline args");
    const json_path = all_args[1];
    std.log.info("verifying JSON files in: {s}", .{json_path});
    var file_count: u32 = 0;
    var json_dir = try std.fs.cwd().openDir(json_path, .{ .iterate = true });
    defer json_dir.close();
    var it = json_dir.iterate();
    while (try it.next()) |entry| {
        switch (entry.kind) {
            .file => {},
            else => |kind| std.debug.panic(
                "unexpected directory entry kind '{t}' for '{s}' in '{s}'",
                .{ kind, entry.name, json_path },
            ),
        }
        std.debug.assert(std.mem.endsWith(u8, entry.name, ".json"));
        try checkFile(arena, json_path, json_dir, entry.name);
        file_count += 1;
    }
    std.log.info("verified {} files", .{file_count});
}

fn checkFile(allocator: std.mem.Allocator, dir_path: []const u8, dir: std.fs.Dir, sub_path: []const u8) !void {
    const content = blk: {
        var file = dir.openFile(sub_path, .{}) catch |err| {
            std.log.err("open '{s}/{s}' failed with {s}", .{ dir_path, sub_path, @errorName(err) });
            std.process.exit(0xff);
        };
        defer file.close();
        break :blk try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    };
    defer allocator.free(content);

    var diagnostics = std.json.Diagnostics{};
    var scanner = std.json.Scanner.initCompleteInput(allocator, content);
    defer scanner.deinit();
    scanner.enableDiagnostics(&diagnostics);
    const json = std.json.parseFromTokenSourceLeaky(
        std.json.Value,
        allocator,
        &scanner,
        .{},
    ) catch |err| {
        std.log.err(
            "{s}{c}{s}:{}:{}: {s}",
            .{
                dir_path,              std.fs.path.sep,         sub_path,
                diagnostics.getLine(), diagnostics.getColumn(), @errorName(err),
            },
        );
        std.process.exit(0xff);
    };
    _ = json;
}
