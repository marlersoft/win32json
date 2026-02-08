pub fn run(
    allocator: std.mem.Allocator,
    name: []const u8,
    argv: []const []const u8,
) !void {
    var child = std.process.Child.init(argv, allocator);
    std.log.info("{f}", .{fmtArgv(child.argv)});
    try child.spawn();
    const term = try child.wait();
    if (childProcFailed(term)) {
        errExit("{s} {f}", .{ name, fmtTerm(term) });
    }
}

pub fn childProcFailed(term: std.process.Child.Term) bool {
    return switch (term) {
        .Exited => |code| code != 0,
        .Signal => true,
        .Stopped => true,
        .Unknown => true,
    };
}

pub fn fmtArgv(argv: []const []const u8) FormatArgv {
    return .{ .argv = argv };
}
const FormatArgv = struct {
    argv: []const []const u8,
    pub fn format(self: @This(), writer: *std.Io.Writer) error{WriteFailed}!void {
        var prefix: []const u8 = "";
        for (self.argv) |arg| {
            try writer.print("{s}{s}", .{ prefix, arg });
            prefix = " ";
        }
    }
};

pub fn fmtTerm(term: std.process.Child.Term) FormatTerm {
    return .{ .term = term };
}
const FormatTerm = struct {
    term: std.process.Child.Term,
    pub fn format(self: @This(), writer: *std.Io.Writer) error{WriteFailed}!void {
        switch (self.term) {
            .Exited => |code| try writer.print("exited with code {}", .{code}),
            .Signal => |sig| try writer.print("exited with signal {}", .{sig}),
            .Stopped => |sig| try writer.print("stopped with signal {}", .{sig}),
            .Unknown => |sig| try writer.print("terminated abnormally with signal {}", .{sig}),
        }
    }
};

pub fn makeRepo(path: []const u8) !void {
    std.fs.cwd().access(path, .{}) catch |err| switch (err) {
        error.FileNotFound => try gitInit(path),
        else => |e| return e,
    };
}
fn gitInit(repo: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const tmp_repo = try std.mem.concat(allocator, u8, &.{ repo, ".initializing" });
    defer allocator.free(tmp_repo);
    try std.fs.cwd().deleteTree(tmp_repo);
    try std.fs.cwd().makeDir(tmp_repo);
    try run(allocator, "git init", &.{
        "git",
        "-C",
        tmp_repo,
        "init",
    });
    try std.fs.cwd().rename(tmp_repo, repo);
}

pub fn readSha(sha_file: []const u8) !union(enum) {
    invalid: []const u8,
    good: [40]u8,
} {
    var buffer: [41]u8 = undefined;
    var out_file = std.fs.cwd().openFile(sha_file, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .invalid = "file not found" },
        else => |e| return e,
    };
    defer out_file.close();
    const len = try out_file.readAll(&buffer);
    if (len < 40) return .{ .invalid = "file too small" };
    if (len > 40) return .{ .invalid = "file too big" };
    return .{ .good = buffer[0..40].* };
}

pub fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
