const std = @import("std");
const Build = std.Build;

const version = "25.0.28-preview";

pub fn build(b: *Build) !void {
    const sync_step = b.step("sync", "Sync the generate/main branches");
    b.default_step = sync_step;

    const nofetch = b.option(bool, "nofetch", "disable fetching the generate branch on every build") orelse false;

    const desc_line_prefix = [_]u8{' '} ** 31;
    const sha_file = blk: {
        const exe = b.addExecutable(.{
            .name = "fetchgenerate",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/fetchgenerate.zig"),
                .target = b.graph.host,
            }),
        });
        const run = b.addRunArtifact(exe);
        run.has_side_effects = if (nofetch) false else true;
        run.addDirectoryArg(b.path("generate-branch"));
        const sha_file = run.addOutputFileArg("generate-sha");
        b.step("fetchgenerate", ("Fetches the generate branch in 'generate-branch'\n" ++ desc_line_prefix ++
            "and stores its sha in a file for other\n" ++ desc_line_prefix ++
            "steps to use as an input.")).dependOn(&run.step);
        break :blk sha_file;
    };

    {
        const exe = b.addExecutable(.{
            .name = "sync",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sync.zig"),
                .target = b.graph.host,
            }),
        });
        const run = b.addRunArtifact(exe);
        run.addFileArg(sha_file);
        sync_step.dependOn(&run.step);
    }
    // TODO: default step clones/updates a copy of the "generate" branch
    //       a copy of the repo
    //       into a subdirectory (work/

    // const metadata_nupkg_file = blk: {
    //     const download_winmd_nupkg = b.addSystemCommand(&.{
    //         "curl",
    //         "https://www.nuget.org/api/v2/package/Microsoft.Windows.SDK.Win32Metadata/" ++ version,
    //         "--location",
    //         "--output",
    //     });
    //     break :blk download_winmd_nupkg.addOutputFileArg("win32metadata.nupkg");
    // };

    // const metadata_nupkg_out = blk: {
    //     const zipcmdline = b.dependency("zipcmdline", .{
    //         .target = b.graph.host,
    //     });
    //     const unzip_exe = zipcmdline.artifact("unzip");
    //     const unzip_metadata = b.addRunArtifact(unzip_exe);
    //     unzip_metadata.addFileArg(metadata_nupkg_file);
    //     unzip_metadata.addArg("-d");
    //     break :blk unzip_metadata.addOutputDirectoryArg("nupkg");
    // };

    // const winmd = metadata_nupkg_out.path(b, "Windows.Win32.winmd");
    // b.step(
    //     "show-winmd",
    //     "Print the winmd file path in the cache",
    // ).dependOn(
    //     &PrintLazyPath.create(b, winmd).step,
    // );

    // const gen_step = b.step("gen", "Generate JSON files (in .zig-cache)");

    // const winmd_dep = b.dependency("winmd", .{});
    // const gen_out_dir = blk: {
    //     const exe = b.addExecutable(.{
    //         .name = "genjson",
    //         .root_module = b.createModule(.{
    //             .root_source_file = b.path("src/genjson.zig"),
    //             .target = b.graph.host,
    //         }),
    //     });
    //     exe.root_module.addImport("winmd", winmd_dep.module("winmd"));
    //     const run = b.addRunArtifact(exe);
    //     run.addFileArg(winmd);
    //     const out_dir = run.addOutputDirectoryArg(".");
    //     gen_step.dependOn(&run.step);
    //     break :blk out_dir;
    // };

    // {
    //     // we can't use b.installDirectory because we need to make sure we delete
    //     // all existing files before installing the new ones in case JSON files are removed
    //     // b.installDirectory(.{
    //     //     .source_dir = gen_out_dir,
    //     //     .install_dir = .prefix,
    //     //     .install_subdir = ".",
    //     // });
    //     const install_exe = b.addExecutable(.{
    //         .name = "install",
    //         .root_module = b.createModule(.{
    //             .root_source_file = b.path("src/install.zig"),
    //             .target = b.graph.host,
    //         }),
    //     });
    //     const install = b.addRunArtifact(install_exe);
    //     install.addDirectoryArg(gen_out_dir);
    //     install.addArg(b.pathResolve(&.{ b.build_root.path.?, "win32json", "api" }));
    //     b.getInstallStep().dependOn(&install.step);
    // }

    // const test_step = b.step("test", "Run all the tests");
    // {
    //     const validate_exe = b.addExecutable(.{
    //         .name = "validate",
    //         .root_module = b.createModule(.{
    //             .root_source_file = b.path("src/validate.zig"),
    //             .target = b.graph.host,
    //             .optimize = .Debug,
    //         }),
    //     });
    //     const validate = b.addRunArtifact(validate_exe);
    //     validate.addDirectoryArg(gen_out_dir);
    //     validate.expectExitCode(0);
    //     test_step.dependOn(&validate.step);
    // }
}

// const PrintLazyPath = struct {
//     step: std.Build.Step,
//     lazy_path: Build.LazyPath,
//     pub fn create(
//         b: *Build,
//         lazy_path: Build.LazyPath,
//     ) *PrintLazyPath {
//         const print = b.allocator.create(PrintLazyPath) catch unreachable;
//         print.* = .{
//             .step = std.Build.Step.init(.{
//                 .id = .custom,
//                 .name = "print the given lazy path",
//                 .owner = b,
//                 .makeFn = make,
//             }),
//             .lazy_path = lazy_path,
//         };
//         lazy_path.addStepDependencies(&print.step);
//         return print;
//     }
//     fn make(step: *std.Build.Step, opt: std.Build.Step.MakeOptions) !void {
//         _ = opt;
//         const print: *PrintLazyPath = @fieldParentPtr("step", step);
//         var write_buf: [1024]u8 = undefined;
//         var stdout = std.fs.File.stdout().writer(&write_buf);
//         try stdout.interface.print(
//             "{s}\n",
//             .{print.lazy_path.getPath(step.owner)},
//         );
//         try stdout.interface.flush();
//     }
// };
