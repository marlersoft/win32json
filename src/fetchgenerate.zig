pub fn main() !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    const all_args = try std.process.argsAlloc(allocator);
    // don't care about freeing args

    const cmd_args = all_args[1..];
    if (cmd_args.len != 2) {
        std.log.err("expected 2 cmdline arguments but got {}", .{cmd_args.len});
        return 1;
    }
    const gen_repo = cmd_args[0];
    const out_file_path = cmd_args[1];

    try common.makeRepo(gen_repo);

    const repo_url = "https://github.com/marlersoft/win32json";
    try common.run(allocator, "git fetch", &.{
        "git",
        "-C",
        gen_repo,
        "fetch",
        repo_url,
        "generate",
    });

    const latest_sha = blk: {
        const argv = [_][]const u8{
            "git",
            "-C",
            gen_repo,
            "rev-parse",
            "FETCH_HEAD",
        };
        std.log.info("{f}", .{common.fmtArgv(&argv)});
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &argv,
        });
        // don't free stdout, we're using it
        //defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.stderr.len > 0) {
            var fw = std.fs.File.stderr().writer(&.{});
            try fw.interface.writeAll(result.stderr);
        }
        if (common.childProcFailed(result.term))
            errExit("git rev-parse {f}", .{common.fmtTerm(result.term)});
        break :blk std.mem.trimRight(u8, result.stdout, "\r\n");
    };
    if (latest_sha.len != 40) errExit(
        "expected sha from git rev-parse to be 40 characters but got {}: '{s}'",
        .{ latest_sha.len, latest_sha },
    );
    std.log.info("latest generate sha: {s}", .{latest_sha});

    switch (try common.readSha(out_file_path)) {
        .invalid => |reason| {
            std.log.info("existing generate sha: invalid: {s}", .{reason});
        },
        .good => |existing_sha| {
            std.log.info("existing generate sha: {s}", .{existing_sha});
            if (std.mem.eql(u8, &existing_sha, latest_sha)) {
                std.log.info("status: already up-to-date", .{});
                return 0;
            }
            std.log.info("status: needs update", .{});
        },
    }

    {
        var file = try std.fs.cwd().createFile(out_file_path, .{});
        defer file.close();
        var fw = file.writer(&.{});
        try fw.interface.writeAll(latest_sha);
    }

    // sanity check
    switch (try common.readSha(out_file_path)) {
        .invalid => |reason| errExit("can't read sha after writing it: {s}", .{reason}),
        .good => |sha_from_file| if (!std.mem.eql(u8, &sha_from_file, latest_sha)) errExit(
            "sha changed to '{s}'",
            .{sha_from_file},
        ),
    }
    std.log.info("{s}", .{out_file_path});
    return 0;
}

const errExit = common.errExit;

const std = @import("std");
const common = @import("common.zig");
