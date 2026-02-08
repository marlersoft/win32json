const std = @import("std");
const Build = std.Build;

const version = "25.0.28-preview";

pub fn build(b: *Build) !void {
    const metadata_nupkg_file = blk: {
        const download_winmd_nupkg = b.addSystemCommand(&.{
            "curl",
            "https://www.nuget.org/api/v2/package/Microsoft.Windows.SDK.Win32Metadata/" ++ version,
            "--location",
            "--output",
        });
        break :blk download_winmd_nupkg.addOutputFileArg("win32metadata.nupkg");
    };

    const metadata_nupkg_out = blk: {
        const zipcmdline = b.dependency("zipcmdline", .{
            .target = b.graph.host,
        });
        const unzip_exe = zipcmdline.artifact("unzip");
        const unzip_metadata = b.addRunArtifact(unzip_exe);
        unzip_metadata.addFileArg(metadata_nupkg_file);
        unzip_metadata.addArg("-d");
        break :blk unzip_metadata.addOutputDirectoryArg("nupkg");
    };

    const winmd = metadata_nupkg_out.path(b, "Windows.Win32.winmd");
    const gen_step = b.step("gen", "Generate JSON files (in .zig-cache)");

    const winmd_dep = b.dependency("winmd", .{});
    const gen_out_dir = blk: {
        const exe = b.addExecutable(.{
            .name = "genjson",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/genjson.zig"),
                .target = b.graph.host,
            }),
        });
        exe.root_module.addImport("winmd", winmd_dep.module("winmd"));
        const run = b.addRunArtifact(exe);
        run.addFileArg(winmd);
        const out_dir = run.addOutputDirectoryArg(".");
        gen_step.dependOn(&run.step);
        break :blk out_dir;
    };

    b.installDirectory(.{
        .source_dir = gen_out_dir,
        .install_dir = .prefix,
        .install_subdir = ".",
    });

    const test_step = b.step("test", "Run all the tests");
    {
        const validate_exe = b.addExecutable(.{
            .name = "validate",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/validate.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
            }),
        });
        const validate = b.addRunArtifact(validate_exe);
        validate.addDirectoryArg(gen_out_dir);
        validate.expectExitCode(0);
        test_step.dependOn(&validate.step);
    }
}
