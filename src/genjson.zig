pub const panic = std.debug.FullPanic(struct {
    pub fn panic(
        msg: []const u8,
        ret_addr: ?usize,
    ) noreturn {
        global.context.logErrorPrefix();
        std.debug.defaultPanic(msg, ret_addr);
    }
}.panic);

const global = struct {
    var context: Context = .{};
};

pub fn main() !void {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_instance.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const cmd_args = all_args[1..];
    if (cmd_args.len != 2) errExit("expected 2 cmdline arguments but got {}", .{cmd_args.len});

    const winmd_path = cmd_args[0];
    const out_dir_path = cmd_args[1];

    // TODO: memory map file or read it?
    const winmd_content = blk: {
        var winmd_file = std.fs.cwd().openFile(winmd_path, .{}) catch |err| errExit(
            "failed to open '{s}' with {s}",
            .{ winmd_path, @errorName(err) },
        );
        defer winmd_file.close();
        const size_u64 = try winmd_file.getEndPos();
        const size_usize = std.math.cast(usize, size_u64) orelse errExit(
            "winmd file size {} too big (max {})",
            .{ size_u64, std.math.maxInt(usize) },
        );
        var reader = winmd_file.reader(&.{});
        break :blk try reader.interface.readAlloc(arena, size_usize);
    };

    try std.fs.cwd().deleteTree(out_dir_path);
    var out_dir = try std.fs.cwd().makeOpenPath(out_dir_path, .{});
    defer out_dir.close();

    try go(arena, winmd_content, out_dir);
}

fn go(arena: std.mem.Allocator, winmd_content: []const u8, out_dir: std.fs.Dir) !void {
    const metadata_file_offset = blk: {
        var err: winmd.MetadataError = undefined;
        break :blk winmd.locateMetadata(&err, winmd_content) catch errExit("{f}", .{err});
    };

    const streams = blk: {
        var err: winmd.MetadataError = undefined;
        break :blk winmd.parseStreams(&err, winmd_content, metadata_file_offset) catch errExit("{f}", .{err});
    };

    const tables_stream = streams.tables orelse errExit("missing the tables stream '#~'", .{});
    const tables = blk: {
        var err: winmd.MetadataError = undefined;
        break :blk winmd.parseTables(&err, winmd_content, metadata_file_offset + tables_stream.offset) catch errExit("{f}", .{err});
    };

    var md: Metadata = .{
        .tables = &tables,
        .string_heap = if (streams.strings) |strings| castArray(u8, winmd_content, metadata_file_offset + strings.offset, strings.size) else null,
        .blob_heap = if (streams.blob) |blob| castArray(u8, winmd_content, metadata_file_offset + blob.offset, blob.size) else null,
        .type_map = TypeMap.init(arena, &tables) catch |e| oom(e),
        .interface_map = winmd.Map(.InterfaceImpl).alloc(arena, &tables) catch |e| oom(e),
        .constant_map = winmd.Map(.Constant).alloc(arena, &tables) catch |e| oom(e),
        .layout_map = winmd.Map(.ClassLayout).init(arena, &tables) catch |e| oom(e),
        // reverse for now to match origin C# generator
        .custom_attr_map = winmd.Map(.CustomAttr).alloc(arena, &tables, .{ .reverse = true }) catch |e| oom(e),
        .nested_map = winmd.Map(.NestedClass).alloc(arena, &tables) catch |e| oom(e),
        .impl_map_map = winmd.Map(.ImplMap).alloc(arena, &tables) catch |e| oom(e),
    };

    defer {
        md.type_map.deinit(arena);
        md.interface_map.deinit(arena);
        md.constant_map.deinit(arena);
        md.layout_map.deinit(arena);
        md.custom_attr_map.deinit(arena);
        md.nested_map.deinit(arena);
        md.impl_map_map.deinit(arena);
    }

    // first scan all top-level types and sort them by namespace
    var api_map: std.StringHashMapUnmanaged(Api) = .{};

    for (0..tables.row_counts.TypeDef) |type_def_index| {
        const type_def = tables.row(.TypeDef, type_def_index);

        const name = md.getString(type_def.name);
        const namespace = md.getString(type_def.namespace);
        if (type_def.attributes.visibility.isNested()) {
            std.debug.assert(std.mem.eql(u8, namespace, ""));
            continue;
        }

        if (std.mem.eql(u8, namespace, "")) {
            if (std.mem.eql(u8, name, "<Module>")) continue;
            @panic("unexpected");
        }

        const api_name = apiFromNamespace(namespace);
        const entry = api_map.getOrPut(arena, api_name) catch |e| oom(e);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{};
        }
        const api = entry.value_ptr;

        // The "Apis" type is a specially-named type reserved to contain all the constant
        // and function declarations for an api.
        if (std.mem.eql(u8, name, "Apis")) {
            enforce(
                api.apis_type_def_index == null,
                "multiple 'Apis' types in the same namespace",
                .{},
            );
            api.apis_type_def_index = @intCast(type_def_index);
        } else {
            api.type_defs.append(arena, @intCast(type_def_index)) catch |e| oom(e);
        }
    }

    const api_patch_map = patch.apiPatchMap(arena) catch |e| oom(e);

    {
        var it = api_map.iterator();
        var api_index: usize = 0;
        while (it.next()) |entry| : (api_index += 1) {
            const name = entry.key_ptr.*;
            const api = entry.value_ptr;
            const api_patches: patch.ApiPatches = api_patch_map.get(name) orelse .none;

            var basename_buf: [200]u8 = undefined;
            const basename = std.fmt.bufPrint(&basename_buf, "{s}.json", .{name}) catch @panic(
                "increase size of basename_buf",
            );

            std.log.info(
                "{}/{}: generating {s} with {} types",
                .{ api_index + 1, api_map.count(), basename, api.type_defs.items.len },
            );
            var file = try out_dir.createFile(basename, .{});
            defer file.close();
            var write_buf: [4096]u8 = undefined;
            var file_writer = file.writer(&write_buf);
            generateApi(&file_writer.interface, &md, name, api, &api_patches) catch |err| switch (err) {
                error.WriteFailed => return file_writer.err.?,
            };
            file_writer.interface.flush() catch return file_writer.err.?;
        }
    }

    patch.verifyApiPatches(&api_patch_map);
}

fn castArray(comptime Element: type, winmd_content: []const u8, offset: u64, len: u64) []align(1) const Element {
    const array_size: u64 = len * @sizeOf(Element);
    if (offset + array_size > winmd_content.len) errExit(
        "file truncated, required {}-bytes (array of {s}) at offset {}",
        .{ array_size, @typeName(Element), offset },
    );
    return @as([*]align(1) const Element, @ptrCast(winmd_content.ptr + offset))[0..len];
}

const shared_namespace_prefix = "Windows.Win32.";
fn apiFromNamespace(namespace: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, namespace, shared_namespace_prefix)) std.debug.panic(
        "Unexpected Namespace '{s}' (does not start with '{s}')",
        .{ namespace, shared_namespace_prefix },
    );
    return namespace[shared_namespace_prefix.len..];
}

fn enforce(cond: bool, comptime fmt: []const u8, args: anytype) void {
    if (!cond) std.debug.panic(fmt, args);
}

const Api = struct {
    // The special "Apis" type whose fields are constants and methods are functions
    apis_type_def_index: ?u32 = null,
    type_defs: std.ArrayListUnmanaged(u32) = .{},
};

const constant_filters_by_api = std.StaticStringMap(std.StaticStringMap(void)).initComptime(.{
    .{
        "Media.MediaFoundation",
        std.StaticStringMap(void).initComptime(.{
            // It seems these values have Custom GuidAttribute's with values that don't
            // have enough bytes in their value to construct a Guid attribute
            .{ "MEDIASUBTYPE_P208", {} },
            .{ "MEDIASUBTYPE_P210", {} },
            .{ "MEDIASUBTYPE_P216", {} },
            .{ "MEDIASUBTYPE_P010", {} },
            .{ "MEDIASUBTYPE_P016", {} },
            .{ "MEDIASUBTYPE_Y210", {} },
            .{ "MEDIASUBTYPE_Y216", {} },
            .{ "MEDIASUBTYPE_P408", {} },
            .{ "MEDIASUBTYPE_P210", {} },
        }),
    },
});

// Workaround https://github.com/microsoft/win32metadata/issues/737
// These are struct types that have GUIDs but are not Com Types
const not_com_by_api = std.StaticStringMap(std.StaticStringMap(void)).initComptime(.{
    .{
        "System.Iis",
        std.StaticStringMap(void).initComptime(.{
            .{ "CONFIGURATION_ENTRY", {} },
            .{ "LOGGING_PARAMETERS", {} },
            .{ "PRE_PROCESS_PARAMETERS", {} },
            .{ "POST_PROCESS_PARAMETERS", {} },
        }),
    },
});

fn generateApi(
    writer: *std.Io.Writer,
    md: *const Metadata,
    api_name: []const u8,
    api: *const Api,
    patches: *const patch.ApiPatches,
) error{WriteFailed}!void {
    global.context.set(.api, api_name);
    defer global.context.unset(.api, api_name);

    try writer.writeAll("{\n");

    const constant_filter = constant_filters_by_api.get(api_name) orelse std.StaticStringMap(void).initComptime(.{});

    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    var constants_filtered: std.StringHashMapUnmanaged(void) = .{};
    defer constants_filtered.deinit(arena);

    {
        var prefix: FirstOnce("\"Constants\":[", "}") = .{};
        var sep: FirstOnce("", ",") = .{};

        const fields: winmd.RowRange = if (api.apis_type_def_index) |i| md.tables.typeDefRange(i, .fields) else .empty;
        for (fields.start..fields.limit) |field_index| {
            const field = md.tables.row(.Field, field_index);
            const name = md.getString(field.name);
            if (constant_filter.get(name)) |_| {
                std.log.info("filtering constant '{s}' (api {s})", .{ name, api_name });
                constants_filtered.put(arena, name, {}) catch |e| oom(e);
                continue;
            }
            var it = md.custom_attr_map.getIterator(.init(.Field, @intCast(field_index)));
            const value = try analyzeConstValue(md, &it, field, name);

            const field_type = md.getBlob(field.signature);
            if (field_type.len == 0) errExit("invalid type signature (empty)", .{});
            if (field_type[0] != 6) errExit("invalid type signature (not field 0x{x})", .{field_type[0]});
            const @"type" = field_type[1..];
            try writer.print("{s}{s}{{\n", .{ prefix.next(), sep.next() });
            try writer.print("\t\"Name\":\"{s}\"\n", .{name});
            try writer.print("\t,\"Type\":{f}\n", .{fmtTypeJson(md, api_name, @"type")});
            switch (value) {
                .guid => |guid| {
                    try writer.print("\t,\"ValueType\":\"String\"\n", .{});
                    try writer.print("\t,\"Value\":{f}\n", .{fmtGuid(guid)});
                },
                .property_key => |key| {
                    try writer.print("\t,\"ValueType\":\"PropertyKey\"\n", .{});
                    try writer.print(
                        "\t,\"Value\":{{\"Fmtid\":{f},\"Pid\":{}}}\n",
                        .{ fmtGuid(key.guid), key.pid },
                    );
                },
                .default => {
                    const coded_index: winmd.ConstantParent = .init(.Field, @intCast(field_index));
                    const constant_index = md.constant_map.get(coded_index) orelse std.debug.panic(
                        "constant '{s}' has default value but no entry in constant table",
                        .{name},
                    );
                    const constant = md.tables.row(.Constant, constant_index);
                    const constant_type: u8 = @intCast(0xff & constant.type);
                    const encoded_value = md.getBlob(constant.value);
                    try writer.print("\t,\"ValueType\":{f}\n", .{fmtValueTypeJson(constant_type)});
                    try writer.writeAll("\t,\"Value\":");
                    switch (winmd.ElementType.decode(constant_type) orelse @panic("invalid type byte")) {
                        // .void => try writer.writeAll("\"Void\""),
                        // .boolean => try writer.writeAll("\"Boolean\""),
                        // .char => try writer.writeAll("\"Char\""),
                        // .i1 => try writer.writeAll("\"SByte\""),
                        .u1 => try writeConstValue(writer, u8, encoded_value),
                        // .i2 => try writeConstValue(writer, i16, encoded_value),
                        .u2 => try writeConstValue(writer, u16, encoded_value),
                        .i4 => try writeConstValue(writer, i32, encoded_value),
                        .u4 => try writeConstValue(writer, u32, encoded_value),
                        .i8 => try writeConstValue(writer, i64, encoded_value),
                        .u8 => try writeConstValue(writer, u64, encoded_value),
                        .r4 => try writeConstValue(writer, f32, encoded_value),
                        .r8 => try writeConstValue(writer, f64, encoded_value),
                        .string => {
                            if (encoded_value.len == 0) {
                                try writer.writeAll("null");
                            } else {
                                try writer.writeAll("\"");
                                const ptr: [*]align(1) const u16 = @ptrCast(@alignCast(encoded_value.ptr));
                                const slice_u16 = ptr[0..@divTrunc(encoded_value.len, 2)];
                                for (slice_u16) |c| {
                                    const one_char = [_]u16{c};
                                    switch (c) {
                                        0x00,
                                        0x0f,
                                        0x10,
                                        0x1e,
                                        => try writer.print("\\u{x:0>4}", .{c}),
                                        '\n' => try writer.writeAll("\\n"),
                                        '\\' => try writer.writeAll("\\\\"),
                                        else => try writer.print("{f}", .{std.unicode.fmtUtf16Le(&one_char)}),
                                    }
                                }
                                try writer.writeAll("\"");
                            }
                        },
                        else => |n| std.debug.panic("unhandled element type {s}", .{@tagName(n)}),
                    }
                    try writer.writeAll("\n");
                },
            }
            try writer.print("\t,\"Attrs\":[]\n", .{});
        }
        try writer.print("{s}],\n\n", .{prefix.next()});
    }

    for (constant_filter.keys()) |key| {
        if (null == constants_filtered.get(key)) {
            std.log.err("constant filter api '{s}' name '{s}' was not applied", .{ api_name, key });
            std.process.exit(0xff);
        }
    }

    var unicode_aliases: UnicodeAliases = .{};
    defer unicode_aliases.deinit(arena);

    {
        const not_com_map = not_com_by_api.get(api_name) orelse std.StaticStringMap(void).initComptime(.{});

        var not_com_applied: std.StringHashMapUnmanaged(void) = .{};
        defer not_com_applied.deinit(arena);

        var prefix: FirstOnce("\"Types\":[", "}") = .{};
        var sep: FirstOnce("", ",") = .{};
        for (api.type_defs.items) |type_def_index| {
            try writer.print("{s}{s}{{\n", .{ prefix.next(), sep.next() });
            const type_name = try generateType(
                arena,
                writer,
                md,
                &not_com_map,
                &not_com_applied,
                api_name,
                patches,
                type_def_index,
                .{ .depth = 1 },
            );
            unicode_aliases.add(arena, type_name);
        }
        try writer.print("{s}],\n\n", .{prefix.next()});

        for (not_com_map.keys()) |key| {
            if (null == not_com_applied.get(key)) {
                std.log.err("not com api '{s}' name '{s}' was not applied", .{ api_name, key });
                std.process.exit(0xff);
            }
        }
    }
    {
        const methods: winmd.RowRange = if (api.apis_type_def_index) |i| md.tables.typeDefRange(i, .methods) else .empty;
        var prefix: FirstOnce("\"Functions\":[", "}") = .{};
        var sep: FirstOnce("", ",") = .{};
        for (methods.start..methods.limit) |method_index| {
            try writer.print("{s}{s}{{\n", .{ prefix.next(), sep.next() });
            const name = try generateFunction(
                writer,
                md,
                api_name,
                &patches.func_map,
                method_index,
                .{ .depth = 1 },
                .fixed,
            );
            unicode_aliases.add(arena, name);
        }
        try writer.print("{s}],\n\n", .{prefix.next()});
    }

    try writer.writeAll("\"UnicodeAliases\":[\n");
    {
        var sep: FirstOnce("", ",") = .{};
        var it = unicode_aliases.map.iterator();
        while (it.next()) |entry| switch (entry.value_ptr.*) {
            .base_exists, .a_only, .w_only => {},
            .both => {
                try writer.print("\t{s}\"{s}\"\n", .{ sep.next(), entry.key_ptr.* });
            },
        };
    }
    try writer.writeAll("]\n}\n");
}

const UnicodeAliases = struct {
    map: std.StringArrayHashMapUnmanaged(State) = .{},
    const State = enum {
        base_exists,
        a_only,
        w_only,
        both,
    };
    pub fn deinit(aliases: *UnicodeAliases, allocator: std.mem.Allocator) void {
        aliases.map.deinit(allocator);
    }
    pub fn add(aliases: *UnicodeAliases, allocator: std.mem.Allocator, name: []const u8) void {
        if (name.len <= 1) return;
        const kind: enum { a, w, base }, const key = blk: {
            if (std.mem.endsWith(u8, name, "A")) break :blk .{ .a, name[0 .. name.len - 1] };
            if (std.mem.endsWith(u8, name, "W")) break :blk .{ .w, name[0 .. name.len - 1] };
            break :blk .{ .base, name };
        };
        const entry = aliases.map.getOrPut(allocator, key) catch |e| oom(e);
        const sub_kind: enum { a, w } = switch (kind) {
            .a => .a,
            .w => .w,
            .base => {
                entry.value_ptr.* = .base_exists;
                return;
            },
        };
        if (entry.found_existing) switch (entry.value_ptr.*) {
            .base_exists => return,
            .a_only => if (sub_kind == .w) {
                entry.value_ptr.* = .both;
            },
            .w_only => if (sub_kind == .a) {
                entry.value_ptr.* = .both;
            },
            .both => {},
        } else entry.value_ptr.* = switch (sub_kind) {
            .a => .a_only,
            .w => .w_only,
        };
    }
};

const sigs = struct {
    const PSTR = [_]u8{@intFromEnum(winmd.ElementType.u1)};
    const PWSTR = [_]u8{@intFromEnum(winmd.ElementType.char)};
};

fn getChildSig(md: *const Metadata, sig: []const u8) []const u8 {
    if (sig.len == 0) @panic("sig truncated");
    return switch (winmd.ElementType.decode(sig[0]) orelse @panic("invalid sig")) {
        .ptr => sig[1..],
        .valuetype => {
            const token_bytes = sig[1..];
            if (token_bytes.len == 0) @panic("truncated");
            const token_len = winmd.decodeSigUnsignedLen(token_bytes[0]);
            if (token_bytes.len < token_len.int(usize)) @panic("truncated token");
            const token_encoded: winmd.TypeToken = @enumFromInt(winmd.decodeSigUnsigned(token_bytes[0..token_len.int(usize)]));
            const token = token_encoded.decode() catch @panic("invalid type token");
            switch (token.table) {
                .TypeDef => @panic("todo: a"),
                .TypeRef => {
                    const type_ref = md.tables.row(.TypeRef, token.index);
                    const name = md.getString(type_ref.name);
                    const namespace = md.getString(type_ref.namespace);
                    if (std.mem.eql(u8, namespace, "Windows.Win32.Foundation")) {
                        if (std.mem.eql(u8, name, "PWSTR")) return &sigs.PWSTR;
                        if (std.mem.eql(u8, name, "PSTR")) return &sigs.PSTR;
                    }
                    std.debug.panic("unable to get Child type for '{s}:{s}'", .{ namespace, name });
                },
                .TypeSpec => @panic("TypeSpec unsupported"),
                _ => @panic("invalid table"),
            }
        },
        else => |t| std.debug.panic("\"todo: implement scanSigToChild for {t}\"", .{t}),
    };
}

const JsonStrings = struct {
    writer: *std.Io.Writer,
    line_prefix: LinePrefix,
    sep: FirstOnce("", ",") = .{},
    pub fn finish(strings: *JsonStrings) error{WriteFailed}!void {
        if (!strings.sep.at_first) {
            try strings.writer.print("\n{f}", .{strings.line_prefix});
        }
    }
    pub fn add(strings: *JsonStrings, string: []const u8) error{WriteFailed}!void {
        try strings.writer.print("\n{f}{s}", .{ strings.line_prefix.indent(), strings.sep.next() });
        try strings.writer.print("\"{s}\"", .{string});
    }
};

fn generateFunction(
    writer: *std.Io.Writer,
    md: *const Metadata,
    api_name: []const u8,
    patch_map: *const std.StringHashMapUnmanaged(patch.FuncPatches),
    method_index: usize,
    line_prefix: LinePrefix,
    kind: enum { fixed, ptr, com },
) error{WriteFailed}![]const u8 {
    const method = md.tables.row(.MethodDef, method_index);
    const name = md.getString(method.name);

    global.context.set(.func, name);
    defer global.context.unset(.func, name);

    var no_patches: patch.FuncPatches = .none;
    const patches: *patch.FuncPatches = patch_map.getPtr(name) orelse &no_patches;

    switch (kind) {
        .ptr => try writer.print("{f},\"Kind\":\"FunctionPointer\"\n", .{line_prefix}),
        .fixed, .com => try writer.print("{f}\"Name\":\"{s}\"\n", .{ line_prefix, name }),
    }

    var dll_import: ?[]const u8 = null;
    var set_last_error = false;

    {
        const member_forwarded: winmd.MemberForwarded = .{
            .table = .MethodDef,
            .index = .fromIndex(@intCast(method_index)),
        };
        if (md.impl_map_map.get(member_forwarded)) |impl_map_index| {
            const impl_map = md.tables.row(.ImplMap, impl_map_index);
            set_last_error = impl_map.flags.supports_last_error;
            if (impl_map.import_scope.asIndex()) |import_scope_index| {
                const module_ref = md.tables.row(.ModuleRef, import_scope_index);
                dll_import = md.getString(module_ref.name);
            }
        }
    }

    var platform: ?[]const u8 = null;
    var arches: ?Architectures = null;
    var DoesNotReturn: bool = false;

    var it = md.custom_attr_map.getIterator(.init(.MethodDef, @intCast(method_index)));
    while (it.next()) |custom_attr_index| {
        const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
        const custom_attr = CustomAttr.decode(md, custom_attr_row);
        switch (custom_attr) {
            .SupportedOSPlatform => |p| {
                std.debug.assert(platform == null);
                platform = p;
            },
            .SupportedArchitecture => |a| {
                std.debug.assert(arches == null);
                arches = a;
            },
            .DoesNotReturn => DoesNotReturn = true,
            else => std.debug.panic("unhandled function attribute {}", .{custom_attr}),
        }
    }

    try writer.print("{f},\"SetLastError\":{}\n", .{ line_prefix, set_last_error });
    if (kind == .fixed) {
        try writer.print("{f},\"DllImport\":{f}\n", .{ line_prefix, fmtStringJson(dll_import) });
    }

    const sig_blob = md.getBlob(method.signature);
    if (sig_blob.len < 2) @panic("method signature too short");
    // Method signature format:
    // - Byte 0: Calling convention flags
    // - Next bytes: Parameter count (compressed)
    // - Next bytes: Return type
    // - Next bytes: Parameter types

    const calling_conv = sig_blob[0];
    _ = calling_conv;
    const param_count_len = winmd.decodeSigUnsignedLen(sig_blob[1]);
    const param_count = winmd.decodeSigUnsigned(sig_blob[1..][0..param_count_len.int(usize)]);
    _ = param_count; // Will be used later for parameters
    var sig_offset: usize = 1 + param_count_len.int(usize);

    try writer.print("{f},\"ReturnType\":", .{line_prefix});
    const ret_type_len = writeTypeJson(writer, md, api_name, sig_blob[sig_offset..]) catch |err| {
        std.log.err("Failed to decode return type for method '{s}': {}", .{ name, err });
        @panic("failed to decode return type");
    };
    sig_offset += ret_type_len;
    try writer.writeAll("\n");
    try writer.print("{f},\"ReturnAttrs\":[", .{line_prefix});
    {
        var attr_sep: FirstOnce("", ",") = .{};
        if (patches.queryOptionalReturn()) {
            try writer.print("{s}\"Optional\"", .{attr_sep.next()});
        }
    }
    try writer.writeAll("]\n");
    if (kind != .ptr) {
        try writer.print("{f},\"Architectures\":[{f}]\n", .{ line_prefix, fmtArches(arches) });
        try writer.print("{f},\"Platform\":{f}\n", .{ line_prefix, fmtStringJson(platform) });
    }
    try writer.print("{f},\"Attrs\":[", .{line_prefix});
    {
        var strings: JsonStrings = .{
            .writer = writer,
            .line_prefix = line_prefix,
        };
        if (method.attributes.special_name) try strings.add("SpecialName");
        if (DoesNotReturn) try strings.add("DoesNotReturn");
        if (method.impl_flags.preserve_sig) try strings.add("PreserveSig");
        try strings.finish();
    }
    try writer.writeAll("]\n");

    try writer.print("{f},\"Params\":[\n", .{line_prefix});
    const params = md.tables.methodParams(@intCast(method_index));
    var param_sep: FirstOnce("", ",") = .{};
    for (params.start..params.limit) |param_index| {
        const param = md.tables.row(.Param, param_index);
        if (param.sequence == 0) continue; // Skip return parameter

        const param_name = md.getString(param.name);
        global.context.set(.param, param_name);
        defer global.context.unset(.param, param_name);

        try writer.print(
            "{f}\t{s}{{\"Name\":\"{s}\",\"Type\":",
            .{ line_prefix, param_sep.next(), param_name },
        );

        var maybe_native_array: ?NativeArray = null;

        // TODO: can we remove this second loop over ALL custom attributes?
        {
            var array_it = md.custom_attr_map.getIterator(.init(.Param, @intCast(param_index)));
            while (array_it.next()) |custom_attr_index| {
                const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
                switch (CustomAttr.decode(md, custom_attr_row)) {
                    .NativeArray => |na| {
                        std.debug.assert(maybe_native_array == null);
                        maybe_native_array = na;
                    },
                    else => {},
                }
            }
        }

        const param_type_sig = blk: {
            const remaining = sig_blob[sig_offset..];
            const len = countTypeSigBytes(sig_blob[sig_offset..]) catch |err| std.debug.panic(
                "failed to decode parameter type for '{s}': {}",
                .{ param_name, err },
            );
            break :blk remaining[0..len];
        };
        if (maybe_native_array) |native_array| {
            try writer.print(
                "{{\"Kind\":\"LPArray\",\"NullNullTerm\":false,\"CountConst\":{},\"CountParamIndex\":{},\"Child\":",
                .{ native_array.CountConst, native_array.CountParamIndex },
            );
            const child_sig = getChildSig(md, param_type_sig);
            const len = writeTypeJson(writer, md, api_name, child_sig) catch |e| @panic(@errorName(e));
            std.debug.assert(len == child_sig.len);
            try writer.writeAll("}");
        } else {
            const len = writeTypeJson(writer, md, api_name, param_type_sig) catch |err| std.debug.panic(
                "failed to write parameter type for '{s}': {t}",
                .{ param_name, err },
            );
            if (len != param_type_sig.len) {
                std.log.info("only used {} out of {} signature", .{ len, param_type_sig.len });
            }
            std.debug.assert(len == param_type_sig.len);
        }

        try writer.writeAll(",\"Attrs\":[");
        var attr_sep: FirstOnce("", ",") = .{};
        if (param.attributes.in) {
            try writer.print("{s}\"In\"", .{attr_sep.next()});
        }
        if (param.attributes.out) {
            try writer.print("{s}\"Out\"", .{attr_sep.next()});
        }
        var const_attr = false;
        var custom_it = md.custom_attr_map.getIterator(.init(.Param, @intCast(param_index)));
        while (custom_it.next()) |custom_attr_index| {
            const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
            const custom_attr = CustomAttr.decode(md, custom_attr_row);
            switch (custom_attr) {
                .Const => const_attr = true,
                .ComOutPtr => try writer.print("{s}\"ComOutPtr\"", .{attr_sep.next()}),
                .NotNullTerminated => try writer.print("{s}\"NotNullTerminated\"", .{attr_sep.next()}),
                .NullNullTerminated => try writer.print("{s}\"NullNullTerminated\"", .{attr_sep.next()}),
                .RetVal => try writer.print("{s}\"RetVal\"", .{attr_sep.next()}),
                .FreeWith => |func| try writer.print("{s}{{\"Kind\":\"FreeWith\",\"Func\":\"{s}\"}}", .{ attr_sep.next(), func }),
                .MemorySize => |idx| try writer.print("{s}{{\"Kind\":\"MemorySize\",\"BytesParamIndex\":{}}}", .{ attr_sep.next(), idx }),
                .DoNotRelease => try writer.print("{s}\"DoNotRelease\"", .{attr_sep.next()}),
                .Reserved => try writer.print("{s}\"Reserved\"", .{attr_sep.next()}),
                .NativeArray => {}, // Already handled above
                else => {},
            }
        }
        const optional = blk: {
            if (param.attributes.optional) break :blk true;
            break :blk patches.queryOptionalParam(param_name);
        };
        if (optional) try writer.print("{s}\"Optional\"", .{attr_sep.next()});
        if (const_attr) try writer.print("{s}\"Const\"", .{attr_sep.next()});
        try writer.writeAll("]}\n");
        sig_offset += param_type_sig.len;
    }
    std.debug.assert(sig_offset == sig_blob.len);
    try writer.print("{f}]\n", .{line_prefix});
    return name;
}

const LinePrefix = struct {
    depth: u8,
    pub fn indent(prefix: LinePrefix) LinePrefix {
        return .{ .depth = prefix.depth + 1 };
    }
    pub fn format(prefix: LinePrefix, writer: *std.Io.Writer) error{WriteFailed}!void {
        try writer.splatByteAll('\t', prefix.depth);
    }
};

fn generateType(
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    md: *const Metadata,
    not_com_map: *const std.StaticStringMap(void),
    not_com_applied: *std.StringHashMapUnmanaged(void),
    api_name: []const u8,
    api_patches: *const patch.ApiPatches,
    type_def_index: u32,
    line_prefix: LinePrefix,
) error{WriteFailed}![]const u8 {
    const type_def = md.tables.row(.TypeDef, type_def_index);
    const name = md.getString(type_def.name);

    const save = global.context.type;
    defer global.context.type = save;
    global.context.type = null;
    global.context.set(.type, name);
    defer global.context.unset(.type, name);

    try writer.print("{f}\"Name\":\"{s}\"\n", .{ line_prefix, name });
    var attrs: TypeAttrs = .{ .flags = type_def.attributes };

    {
        var it = md.custom_attr_map.getIterator(.init(.TypeDef, @intCast(type_def_index)));
        while (it.next()) |custom_attr_index| {
            const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
            const custom_attr = CustomAttr.decode(md, custom_attr_row);
            switch (custom_attr) {
                .Guid => |guid| {
                    if (attrs.guid != null) @panic("multiple guids");
                    attrs.guid = guid;
                },
                .RaiiFree => |func| {
                    if (attrs.raii_free != null) @panic("multiple RAIIFree attributes");
                    attrs.raii_free = func;
                },
                .NativeTypedef => {
                    std.debug.assert(!attrs.is_native_typedef);
                    attrs.is_native_typedef = true;
                },
                .Flags => {
                    std.debug.assert(!attrs.is_flags);
                    attrs.is_flags = true;
                },
                .UnmanagedFunctionPointer => {
                    // std.log.warn("TODO: do something with UnmanagedFunctionPointer attribute", .{});
                },
                .AlsoUsableFor => |usable| {
                    std.debug.assert(attrs.also_usable_for == null);
                    attrs.also_usable_for = usable;
                },
                .SupportedOSPlatform => |p| {
                    std.debug.assert(attrs.supported_os_platform == null);
                    attrs.supported_os_platform = p;
                },
                .SupportedArchitecture => |arches| {
                    std.debug.assert(attrs.arches == null);
                    attrs.arches = arches;
                },
                .ScopedEnum => {
                    std.debug.assert(!attrs.scoped_enum);
                    attrs.scoped_enum = true;
                },
                .InvalidHandleValue => |v| {
                    if (attrs.invalid_handle_value != null) {
                        std.log.warn("TODO: handle multiple InvalidHandleValues (type {s})", .{name});
                    }
                    attrs.invalid_handle_value = v;
                },
                .Agile => {
                    std.debug.assert(!attrs.is_agile);
                    attrs.is_agile = true;
                },
                else => std.debug.panic("unexpected custom attribute '{s}' on TypeDef", .{@tagName(custom_attr)}),
            }
        }
    }

    try writer.print("{f},\"Architectures\":[{f}]\n", .{ line_prefix, fmtArches(attrs.arches) });
    try writer.print("{f},\"Platform\":{f}\n", .{ line_prefix, fmtStringJson(attrs.supported_os_platform) });

    if (attrs.is_native_typedef) {
        attrs.verify(.{
            .scoped_enum = .no,
            .free_func = .allowed,
            .layout = null,
            // .field_count == 1,
            .also_usable_for = .allowed,
            .invalid_handle_value = .allowed,
        });
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // TODO: verify maybe_base_type
        try writer.print("{f},\"Kind\":\"NativeTypedef\"\n", .{line_prefix});
        try writer.print("{f},\"AlsoUsableFor\":{f}\n", .{ line_prefix, fmtStringJson(attrs.also_usable_for) });

        const fields = md.tables.typeDefRange(type_def_index, .fields);
        if (fields.limit - fields.start != 1) {
            std.log.warn("NativeTypedef '{s}' has {} fields, expected 1", .{ name, fields.limit - fields.start });
        }

        if (fields.start < fields.limit) {
            const field = md.tables.row(.Field, fields.start);
            const field_type = md.getBlob(field.signature);
            if (field_type.len == 0) errExit("invalid type signature (empty)", .{});
            if (field_type[0] != 6) errExit("invalid type signature (not field 0x{x})", .{field_type[0]});
            const @"type" = field_type[1..];

            try writer.print(
                "{f},\"Def\":{f}\n",
                .{ line_prefix, fmtTypeJson(md, api_name, @"type") },
            );
        } else {
            try writer.print("{f},\"Def\":null\n", .{line_prefix});
        }

        try writer.print("{f},\"FreeFunc\":{f}\n", .{ line_prefix, fmtStringJson(attrs.raii_free) });

        try writer.print("{f},\"InvalidHandleValue\":", .{line_prefix});
        if (attrs.invalid_handle_value) |val| {
            try writer.print("{}", .{val});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("\n");
        return name;
    }

    const target_kind = TargetKind.initTypeDef(md, type_def_index);

    const base_type_index = type_def.extends.value() orelse {
        std.debug.assert(target_kind == .Com);
        attrs.verify(.{
            .scoped_enum = .no,
            .free_func = .no,
            .layout = .auto,
            .also_usable_for = .no,
            .invalid_handle_value = .no,
        });
        try generateCom(
            writer,
            md,
            api_name,
            &api_patches.func_map,
            type_def_index,
            attrs.guid,
            .{
                .Agile = attrs.is_agile,
            },
        );
        return name;
    };
    std.debug.assert(target_kind != .Com);

    const base_type: enum { @"enum", value, delegate } = blk: {
        switch (base_type_index.table) {
            .TypeRef => {},
            else => @panic("unexpected base type table"),
        }
        const base_type_ref = md.tables.row(.TypeRef, base_type_index.index);
        const base_type_qn: QualifiedName = .{
            .namespace = md.getString(base_type_ref.namespace),
            .name = md.getString(base_type_ref.name),
        };

        if (base_type_qn.eql("System", "Enum")) break :blk .@"enum";
        if (base_type_qn.eql("System", "ValueType")) break :blk .value;
        if (base_type_qn.eql("System", "MulticastDelegate")) break :blk .delegate;
        std.debug.panic(
            "unexpected base type Namespace '{s}' Name '{s}'",
            .{ base_type_qn.namespace, base_type_qn.name },
        );
    };

    switch (base_type) {
        .@"enum" => {
            attrs.verify(.{
                .scoped_enum = .allowed,
                .free_func = .no,
                .layout = .auto,
                .also_usable_for = .no,
                .invalid_handle_value = .no,
            });
            try writer.print("{f},\"Kind\":\"Enum\"\n", .{line_prefix});
            try writer.print("{f},\"Flags\":{}\n", .{ line_prefix, attrs.is_flags });
            try writer.print("{f},\"Scoped\":{}\n", .{ line_prefix, attrs.scoped_enum });
            try writer.print("{f},\"Values\":[\n", .{line_prefix});
            const int_base = try generateEnumValues(
                writer,
                md,
                type_def_index,
            );
            try writer.print("{f}]\n", .{line_prefix});
            try writer.print(
                "{f},\"IntegerBase\":{f}\n",
                .{ line_prefix, fmtStringJson(if (int_base) |i| @tagName(i) else null) },
            );
        },
        .value => {
            const maybe_com_guid: ?std.os.windows.GUID = blk: {
                const guid = attrs.guid orelse break :blk null;
                if (not_com_map.get(name)) |_| {
                    //std.log.info("not com '{s}' (api {s})", .{ name, api_name });
                    not_com_applied.put(arena, name, {}) catch |e| oom(e);
                    break :blk null;
                }
                break :blk guid;
            };
            attrs.verify(.{
                .scoped_enum = .no,
                .free_func = .no,
                .layout = if (maybe_com_guid != null) .sequential else null,
                .also_usable_for = .no,
                .invalid_handle_value = .no,
            });
            if (maybe_com_guid) |com_guid| {
                try writer.print("{f},\"Kind\":\"ComClassID\"\n", .{line_prefix});
                try writer.print("{f},\"Guid\":{f}\n", .{ line_prefix, fmtGuid(com_guid) });
                // TypeLayout layout = typeInfo.Def.GetLayout();
                // Enforce.Data(layout.IsDefault);
                // Enforce.Data(layout.Size == 0);
                // Enforce.Data(layout.PackingSize == 0);
                std.debug.assert(md.tables.typeDefRange(type_def_index, .fields).count() == 0);
                std.debug.assert(md.tables.typeDefRange(type_def_index, .methods).count() == 0);
                std.debug.assert(null == md.nested_map.getIterator(type_def_index).index.asIndex());
            } else {
                var no_patches: patch.StructPatches = .none;
                const struct_patches = api_patches.struct_map.getPtr(name) orelse &no_patches;
                try generateStruct(
                    arena,
                    writer,
                    md,
                    not_com_map,
                    not_com_applied,
                    api_name,
                    type_def_index,
                    &attrs,
                    struct_patches,
                    .{ .depth = line_prefix.depth },
                );
            }
        },
        .delegate => {
            std.debug.assert(target_kind == .FunctionPointer);
            std.debug.assert(attrs.guid == null);
            std.debug.assert(!attrs.is_agile);
            attrs.verify(.{
                .scoped_enum = .no,
                .free_func = .no,
                .layout = .auto,
                .also_usable_for = .no,
                .invalid_handle_value = .no,
            });
            try generateFunctionPointer(
                writer,
                md,
                api_name,
                &api_patches.func_map,
                type_def_index,
                line_prefix,
            );
            return name;
        },
    }
    return name;
}

fn generateCom(
    writer: *std.Io.Writer,
    md: *const Metadata,
    api_name: []const u8,
    patch_map: *const std.StringHashMapUnmanaged(patch.FuncPatches),
    type_def_index: u32,
    guid: ?Guid,
    named: struct {
        Agile: bool,
    },
) error{WriteFailed}!void {
    std.debug.assert(md.tables.typeDefRange(type_def_index, .fields).count() == 0);

    try writer.writeAll("\t,\"Kind\":\"Com\"\n");
    try writer.print("\t,\"Guid\":{f}\n", .{fmtGuid(guid)});
    try writer.print("\t,\"Attrs\":[", .{});
    {
        var strings: JsonStrings = .{
            .writer = writer,
            .line_prefix = .{ .depth = 1 },
        };
        if (named.Agile) try strings.add("Agile");
        try strings.finish();
    }
    try writer.writeAll("]\n");

    try writer.writeAll("\t,\"Interface\":");
    if (md.interface_map.get(type_def_index)) |interface| {
        // NOTE: old code would verify the interface has no custom attributes
        try fmtTypeDefOrRef(md, api_name, .{
            .table = switch (interface.table) {
                .TypeDef => @panic("all interfaces are TypeRef's so far"),
                .TypeRef => .TypeRef,
                .TypeSpec => @panic("TypeSpec unsupported"),
                _ => @panic("invalid table"),
            },
            .index = interface.index.asIndex().?,
        }).format(writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll("\n");

    {
        var prefix: FirstOnce(",\"Methods\":[", "}") = .{};
        var sep: FirstOnce("", ",") = .{};
        const methods = md.tables.typeDefRange(type_def_index, .methods);
        for (methods.start..methods.limit) |i| {
            try writer.print("\t{s}{s}{{\n", .{ prefix.next(), sep.next() });
            _ = try generateFunction(
                writer,
                md,
                api_name,
                patch_map,
                i,
                .{ .depth = 2 },
                .com,
            );
        }
        try writer.print("\t{s}]\n", .{prefix.next()});
    }
    std.debug.assert(null == md.nested_map.getIterator(type_def_index).index.asIndex());
}

fn generateFunctionPointer(
    writer: *std.Io.Writer,
    md: *const Metadata,
    api_name: []const u8,
    patch_map: *const std.StringHashMapUnmanaged(patch.FuncPatches),
    type_def_index: u32,
    line_prefix: LinePrefix,
) error{WriteFailed}!void {
    std.debug.assert(md.tables.typeDefRange(type_def_index, .fields).count() == 0);
    std.debug.assert(null == md.nested_map.store.get(type_def_index));
    const methods = md.tables.typeDefRange(type_def_index, .methods);
    std.debug.assert(methods.count() == 2);
    {
        const ctor = md.tables.row(.MethodDef, methods.start);
        const name = md.getString(ctor.name);
        std.debug.assert(std.mem.eql(u8, name, ".ctor"));
    }
    _ = try generateFunction(
        writer,
        md,
        api_name,
        patch_map,
        methods.start + 1,
        line_prefix,
        .ptr,
    );
}

fn FirstOnce(comptime first: []const u8, comptime separator: []const u8) type {
    return struct {
        at_first: bool = true,
        const Self = @This();
        pub fn next(self: *Self) []const u8 {
            if (self.at_first) {
                self.at_first = false;
                return first;
            }
            return separator;
        }
    };
}

const FmtComAttrs = struct {
    Agile: bool,
    pub fn format(f: FmtComAttrs, writer: *std.Io.Writer) error{WriteFailed}!void {
        var sep: FirstOnce("", ",") = .{};
        if (f.Agile) try writer.print("{s}\"Agile\"", .{sep.next()});
    }
};

const FieldAttrs = struct {
    Const: bool = false,
    NotNullTerminated: bool = false,
    NullNullTerminated: bool = false,
    Obsolete: ?struct { Message: ?[]const u8 } = null,
    Optional: bool = false,
    pub fn format(self: FieldAttrs, writer: *std.Io.Writer) error{WriteFailed}!void {
        var sep: FirstOnce("", ",") = .{};
        if (self.Obsolete) |obsolete| {
            _ = obsolete;
            try writer.print("{s}\"Obselete\"", .{sep.next()});
            // try writer.print("{s}{{\"Kind\":\"Obsolete\",\"Message\":\"{s}\"}}", .{
            //     sep.next(), obsolete.Message orelse "",
            // });
        }
        inline for (std.meta.fields(FieldAttrs)) |field| {
            if (comptime !std.mem.eql(u8, field.name, "Obsolete")) {
                if (@field(self, field.name)) {
                    try writer.print("{s}\"{s}\"", .{ sep.next(), field.name });
                }
            }
        }
    }
};

fn generateStruct(
    arena: std.mem.Allocator,
    writer: *std.Io.Writer,
    md: *const Metadata,
    not_com_map: *const std.StaticStringMap(void),
    not_com_applied: *std.StringHashMapUnmanaged(void),
    api_name: []const u8,
    type_def_index: u32,
    attrs: *const TypeAttrs,
    patches: *patch.StructPatches,
    line_prefix: LinePrefix,
) error{WriteFailed}!void {
    const kind: []const u8 = switch (attrs.flags.layout) {
        .sequential => "Struct",
        .explicit => "Union",
        else => |l| std.debug.panic("todo: handle layout {s}", .{@tagName(l)}),
    };
    try writer.print("{f},\"Kind\":\"{s}\"\n", .{ line_prefix, kind });

    const packing_size = blk: {
        const layout_index = md.layout_map.get(type_def_index) orelse break :blk 0;
        const layout = md.tables.row(.ClassLayout, layout_index);
        break :blk layout.packing_size;
    };
    try writer.print("{f},\"Size\":0\n", .{line_prefix});
    try writer.print("{f},\"PackingSize\":{d}\n", .{ line_prefix, packing_size });
    try writer.print("{f},\"Fields\":[\n", .{line_prefix});

    var const_field_count: usize = 0;
    const const_field_attrs: winmd.FieldAttributes = .{
        .access = .public,
        .static = true,
        .literal = true,
        .has_default = true,
    };

    const fields = md.tables.typeDefRange(type_def_index, .fields);
    {
        var field_sep: FirstOnce("", ",") = .{};
        for (fields.start..fields.limit) |field_index| {
            const field = md.tables.row(.Field, field_index);
            if (field.attributes == const_field_attrs) {
                // I'm not sure whether the metadata intended to put constants inside types like this or if they
                // should be moved to the special "Api" type.  If so, I'll have to put them somewhere, not sure where yet though.
                // I could add a "Constants" subfield, but right now only 2 types have these const fields so it's not worth adding
                // this extra field to every single type just to accomodate some const fields on a couple types.
                // Maybe I should open a github issue about this?  Ask why these are the only 2 types using const fields.
                // std.debug.assert(
                // Enforce.Data(typeInfo.Name == "WSDXML_NODE" || typeInfo.Name == "WhitePoint");
                // Enforce.Data(fieldDef.GetCustomAttributes().Count == 0);
                // Enforce.Data(fieldDef.GetOffset() == -1);
                // Constant constant = this.mr.GetConstant(fieldDef.GetDefaultValue());
                // string value = constant.ReadConstValue(this.mr);
                // constFields.Add(Fmt.In($"{constant.TypeCode} {fieldName} = {value}"));
                const_field_count += 1;
                continue;
            }

            const name = md.getString(field.name);
            const field_type = md.getBlob(field.signature);
            if (field_type.len == 0) errExit("invalid type signature (empty)", .{});
            if (field_type[0] != 6) errExit("invalid type signature (not field 0x{x})", .{field_type[0]});
            const @"type" = field_type[1..];

            var field_attrs: FieldAttrs = .{};
            var maybe_native_array: ?NativeArray = null;

            var it = md.custom_attr_map.getIterator(.init(.Field, @intCast(field_index)));
            while (it.next()) |custom_attr_index| {
                const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
                const custom_attr = CustomAttr.decode(md, custom_attr_row);
                switch (custom_attr) {
                    .Const => field_attrs.Const = true,
                    .NotNullTerminated => field_attrs.NotNullTerminated = true,
                    .NullNullTerminated => field_attrs.NullNullTerminated = true,
                    .Obsolete => |obsolete| field_attrs.Obsolete = .{ .Message = obsolete.Message },
                    .NativeArray => |na| {
                        std.debug.assert(maybe_native_array == null);
                        maybe_native_array = na;
                    },
                    else => std.debug.panic("unhandled field custom attr '{s}'", .{@tagName(custom_attr)}),
                }
            }
            field_attrs.Optional = patches.queryOptionalField(name);

            try writer.print(
                "{f}\t{s}{{\"Name\":\"{s}\",\"Type\":",
                .{ line_prefix, field_sep.next(), name },
            );
            if (maybe_native_array) |native_array| {
                try writer.print(
                    "{{\"Kind\":\"LPArray\",\"NullNullTerm\":false,\"CountConst\":{},\"CountParamIndex\":{},\"Child\":",
                    .{ native_array.CountConst, native_array.CountParamIndex },
                );
                const child_sig = getChildSig(md, @"type");
                const len = writeTypeJson(writer, md, api_name, child_sig) catch |e| @panic(@errorName(e));
                std.debug.assert(len == child_sig.len);
                try writer.writeAll("}");
            } else {
                try writer.print("{f}", .{fmtTypeJson(md, api_name, @"type")});
            }
            try writer.print(",\"Attrs\":[{f}]}}\n", .{field_attrs});
        }
    }
    try writer.print("{f}]\n", .{line_prefix});

    if (const_field_count > 0) {
        try writer.print("{f},\"Comment\":\"This type has {} const fields, not sure if it's supposed to:", .{ line_prefix, const_field_count });
        var sep: FirstOnce("", ",") = .{};
        for (fields.start..fields.limit) |field_index| {
            const field = md.tables.row(.Field, field_index);
            if (field.attributes == const_field_attrs) {
                const name = md.getString(field.name);
                const field_type = md.getBlob(field.signature);
                const type_string = switch (field_type[1]) {
                    @intFromEnum(winmd.ElementType.i4) => "Int32",
                    else => |b| std.debug.panic("todo: handle type {}", .{b}),
                };
                try writer.print("{s} {s} {s}", .{ sep.next(), type_string, name });
            }
        }
        try writer.writeAll("\"\n");
    }

    {
        var prefix: FirstOnce(",\"NestedTypes\":[", "}") = .{};
        var sep: FirstOnce("", ",") = .{};

        var iterator = md.nested_map.getIterator(type_def_index);
        while (iterator.next()) |nested_class_index| {
            const entry = md.tables.row(.NestedClass, nested_class_index);
            std.debug.assert(entry.enclosing.asIndex().? == type_def_index);
            const nested_type_def_index = entry.nested.asIndex().?;
            try writer.print("{f}{s}{s}{{\n", .{ line_prefix, prefix.next(), sep.next() });
            const type_def = md.tables.row(.TypeDef, nested_type_def_index);
            std.debug.assert(type_def.attributes.visibility.isNested());
            const no_patches: patch.ApiPatches = .none;
            _ = try generateType(
                arena,
                writer,
                md,
                not_com_map,
                not_com_applied,
                api_name,
                &no_patches,
                nested_type_def_index,
                .{ .depth = line_prefix.depth + 1 },
            );
        }
        try writer.print("{f}{s}]\n", .{ line_prefix, prefix.next() });
    }
}

fn fmtStringJson(s: ?[]const u8) FmtStringJson {
    return .{ .s = s };
}
const FmtStringJson = struct {
    s: ?[]const u8,
    pub fn format(self: FmtStringJson, writer: *std.Io.Writer) error{WriteFailed}!void {
        if (self.s) |s| {
            try writer.print("\"{s}\"", .{s});
        } else {
            try writer.writeAll("null");
        }
    }
};
// const NullableOptions = struct {
//     quote: bool = false,
// };
// fn fmtNullable(comptime T: type, nullable: ?T, options: NullableOptions) FmtNullable(T) {
//     return .{ .nullable = nullable, .options = options };
// }
// fn FmtNullable(comptime T: type) type {
//     return struct {
//         nullable: ?T,
//         options: NullableOptions,

//         const Self = @This();
//         pub fn format(
//             self: Self,
//             comptime spec: []const u8,
//             options: std.fmt.FormatOptions,
//             writer: anytype,
//         ) !void {
//             _ = options;
//             if (self.nullable) |val| {
//                 const quote: []const u8 = if (self.options.quote) "\"" else "";
//                 try writer.print("{s}{" ++ spec ++ "}{s}", .{ quote, val, quote });
//             } else {
//                 try writer.writeAll("null");
//             }
//         }
//     };
// }

fn generateEnumValues(
    writer: *std.Io.Writer,
    md: *const Metadata,
    enum_type_def_index: u32,
) error{WriteFailed}!?EnumBase {
    const values = md.tables.typeDefRange(enum_type_def_index, .fields);
    var maybe_base: ?EnumBase = null;

    var sep: []const u8 = "";
    for (values.start..values.limit) |field_index| {
        const field = md.tables.row(.Field, field_index);
        const name = md.getString(field.name);

        if (field.attributes == winmd.FieldAttributes{
            .access = .public,
            .static = false,
            .special_name = true,
            .rt_special_name = true,
        }) {
            std.debug.assert(std.mem.eql(u8, name, "value__"));
            continue;
        }
        data_assert(field.attributes == winmd.FieldAttributes{
            .access = .public,
            .static = true,
            .literal = true,
            .has_default = true,
        });

        const coded_index: winmd.ConstantParent = .init(.Field, @intCast(field_index));
        const constant_index = md.constant_map.get(coded_index) orelse std.debug.panic(
            "constant '{s}' has default value but no entry in constant table",
            .{name},
        );
        const constant = md.tables.row(.Constant, constant_index);
        const encoded_value = md.getBlob(constant.value);
        const base_type: EnumBase = switch (winmd.ElementType.decodeU32(
            constant.type,
        ) orelse @panic("invalid constant type")) {
            .i1 => .SByte,
            .u1 => .Byte,
            .u2 => .UInt16,
            .i4 => .Int32,
            .u4 => .UInt32,
            .u8 => .UInt64,
            else => |t| std.debug.panic("todo: support value type '{s}'", .{@tagName(t)}),
        };
        if (maybe_base) |b| {
            std.debug.assert(b == base_type);
        } else {
            maybe_base = base_type;
        }

        // TODO: enforce there are 0 custom attributes
        try writer.print(
            "\t\t{s}{{\"Name\":\"{s}\",\"Value\":",
            .{ sep, name },
        );
        try writeEnumValue(writer, base_type, encoded_value);
        try writer.writeAll("}\n");
        sep = ",";
    }

    return maybe_base;
}
const EnumBase = enum {
    SByte,
    Byte,
    UInt16,
    Int32,
    UInt32,
    UInt64,
    pub fn Type(self: EnumBase) type {
        return switch (self) {
            .SByte => i8,
            .Byte => u8,
            .UInt16 => u16,
            .Int32 => i32,
            .UInt32 => u32,
            .UInt64 => u64,
        };
    }
};

fn data_assert(cond: bool) void {
    if (!cond) @panic("data assertion failed");
}

const TypeAttrs = struct {
    flags: winmd.TypeAttributes,
    guid: ?Guid = null,
    is_native_typedef: bool = false,
    is_flags: bool = false,
    raii_free: ?[]const u8 = null,
    also_usable_for: ?[]const u8 = null,
    supported_os_platform: ?[]const u8 = null,
    arches: ?Architectures = null,
    scoped_enum: bool = false,
    invalid_handle_value: ?u64 = null,
    is_agile: bool = false,
    pub fn verify(self: *const TypeAttrs, o: struct {
        scoped_enum: enum { no, allowed },
        free_func: enum { no, allowed },
        layout: ?winmd.Layout,
        also_usable_for: enum { no, allowed },
        invalid_handle_value: enum { no, allowed },
    }) void {
        switch (o.scoped_enum) {
            .no => std.debug.assert(self.scoped_enum == false),
            .allowed => {},
        }
        switch (o.free_func) {
            .no => std.debug.assert(self.raii_free == null),
            .allowed => {},
        }
        if (o.layout) |l| std.debug.assert(l == self.flags.layout);
        // if (o.layout) |l| {
        //     if (l == self.flags.layout) {
        //         //std.log.info("Layout: MATCH {s}", .{@tagName(l)});
        //     } else {
        //         std.log.info("Layout: Mismatch expected {s} got {s}", .{ @tagName(l), @tagName(self.flags.layout) });
        //     }
        // }
        switch (o.also_usable_for) {
            .no => std.debug.assert(self.also_usable_for == null),
            .allowed => {},
        }
        switch (o.invalid_handle_value) {
            .no => std.debug.assert(self.invalid_handle_value == null),
            .allowed => {},
        }
    }
};

const ConstantValue = union(enum) {
    guid: Guid,
    property_key: PropertyKey,
    default: void,
};
fn analyzeConstValue(
    md: *const Metadata,
    custom_attrs: *winmd.LinkIterator,
    field: winmd.Row(.Field),
    name: []const u8,
) !ConstantValue {
    const has_value_attributes: winmd.FieldAttributes = .{
        .access = .public,
        .static = true,
        .literal = true,
        .has_default = true,
    };
    const no_value_attributes: winmd.FieldAttributes = .{
        .access = .public,
        .static = true,
    };
    const has_default_value = if (field.attributes == has_value_attributes)
        true
    else if (field.attributes == no_value_attributes)
        false
    else
        errExit("unexpected constant field definition attributes: {}", .{field.attributes});

    var maybe_guid: ?Guid = null;
    var maybe_property_key: ?PropertyKey = null;

    while (custom_attrs.next()) |custom_attr_index| {
        const custom_attr_row = md.tables.row(.CustomAttr, custom_attr_index);
        const custom_attr = CustomAttr.decode(md, custom_attr_row);
        switch (custom_attr) {
            .Guid => |guid| {
                if (maybe_guid != null) @panic("multiple guids");
                maybe_guid = guid;
            },
            .PropertyKey => |key| {
                if (maybe_property_key != null) @panic("multiple property keys");
                maybe_property_key = key;
            },
            else => |c| std.debug.panic("unexpected custom attribute '{s}'", .{@tagName(c)}),
        }
    }

    if (maybe_guid) |guid| {
        if (has_default_value) std.debug.panic("constant '{s}' has default value and guid", .{name});
        if (maybe_property_key != null) @panic("has guid and property key");
        return .{ .guid = guid };
    } else if (maybe_property_key) |key| {
        if (has_default_value) @panic("has default value and property  key");
        return .{ .property_key = key };
    }
    if (!has_default_value) @panic("has no default value, guid nor property key");
    return .default;
}

fn withinFixedPointRange(comptime T: type, float: T) bool {
    if (float == 0) return true;
    return @abs(float) >= 1e-4 and @abs(float) < 1.7e7;
}

fn writeEnumValue(writer: *std.Io.Writer, base: EnumBase, bytes: []const u8) error{WriteFailed}!void {
    switch (base) {
        inline else => |t| try writeConstValue(writer, t.Type(), bytes),
    }
}
fn writeConstValue(writer: *std.Io.Writer, comptime T: type, bytes: []const u8) error{WriteFailed}!void {
    std.debug.assert(bytes.len == @sizeOf(T));
    switch (@typeInfo(T)) {
        .int => try writer.print("{d}", .{std.mem.readInt(T, bytes[0..@sizeOf(T)], .little)}),
        .float => {
            const Int = @Type(.{ .int = .{ .bits = 8 * @sizeOf(T), .signedness = .unsigned } });
            const value: T = @bitCast(std.mem.readInt(Int, bytes[0..@sizeOf(T)], .little));
            if (withinFixedPointRange(T, value)) {
                try writer.print("{d}", .{value});
            } else {
                var buf: [100]u8 = undefined;
                const str = std.fmt.bufPrint(&buf, "{e}", .{value}) catch unreachable;
                const e_index = std.mem.indexOfScalar(u8, str, 'e') orelse unreachable;
                const mantissa = str[0..e_index];
                const exp = str[e_index + 1 ..];
                const sign: []const u8 = if (exp[0] == '-') "" else "+";
                try writer.print("{s}E{s}{s:0>2}", .{ mantissa, sign, exp });
            }
        },
        else => @compileError("todo: support type " ++ @typeName(T)),
    }
}

const Guid = std.os.windows.GUID;
fn fmtGuid(guid: ?Guid) FmtGuid {
    return .{ .guid = guid };
}
const FmtGuid = struct {
    guid: ?Guid,
    pub fn format(self: FmtGuid, writer: *std.Io.Writer) error{WriteFailed}!void {
        const guid = self.guid orelse return try writer.writeAll("null");
        try writer.print(
            "\"{x:0>8}-{x:0>4}-{x:0>4}-{x:0>2}{x:0>2}-{x}\"",
            .{
                guid.Data1,
                guid.Data2,
                guid.Data3,
                guid.Data4[0],
                guid.Data4[1],
                guid.Data4[2..],
            },
        );
    }
};
fn fmtArches(arches: ?Architectures) FmtArches {
    return .{ .arches = arches };
}
const FmtArches = struct {
    arches: ?Architectures,
    pub fn format(self: FmtArches, writer: *std.Io.Writer) error{WriteFailed}!void {
        const arches = self.arches orelse return;
        var sep: FirstOnce("", ",") = .{};
        if (arches.X86) try writer.print("{s}\"X86\"", .{sep.next()});
        if (arches.X64) try writer.print("{s}\"X64\"", .{sep.next()});
        if (arches.Arm64) try writer.print("{s}\"Arm64\"", .{sep.next()});
    }
};

const PropertyKey = struct {
    guid: Guid,
    pid: u32,
};

const NativeArray = struct {
    CountConst: i32,
    CountParamIndex: i16,
};

const Architectures = packed struct(u32) {
    X86: bool,
    X64: bool,
    Arm64: bool,
    reserved: u29,
};

const CustomAttr = union(enum) {
    Guid: Guid,
    PropertyKey: PropertyKey,
    NativeTypedef,
    Flags,
    RaiiFree: []const u8,
    UnmanagedFunctionPointer,
    AlsoUsableFor: []const u8,
    SupportedOSPlatform: []const u8,
    SupportedArchitecture: Architectures,
    ScopedEnum,
    DoNotRelease,
    Reserved,
    InvalidHandleValue: u64,
    Agile,
    Const,
    NativeArray: NativeArray,
    Obsolete: struct {
        Message: ?[]const u8,
    },
    NotNullTerminated,
    NullNullTerminated,
    ComOutPtr,
    RetVal,
    FreeWith: []const u8,
    MemorySize: i16,
    DoesNotReturn,
    pub fn decode(
        md: *const Metadata,
        custom_attr: winmd.Row(.CustomAttr),
    ) CustomAttr {
        const value_blob = md.getBlob(custom_attr.value);
        if (!std.mem.startsWith(u8, value_blob, &[_]u8{ 1, 0 })) @panic("CustomAttr value unexpected prolog");
        const value = value_blob[2..];
        switch (custom_attr.method.table) {
            .MethodDef => @panic("todo"),
            .MemberRef => {
                const member_ref = md.tables.row(.MemberRef, custom_attr.method.index.asIndex().?);
                const signature = md.getBlob(member_ref.signature);
                if (signature[0] != 0x20) @panic("unexpected MemberRef sig");
                switch (member_ref.parent.table) {
                    .TypeRef => {
                        const type_ref = md.tables.row(.TypeRef, member_ref.parent.index.asIndex().?);
                        return decodeCustomAttr(.{
                            .namespace = md.getString(type_ref.namespace),
                            .name = md.getString(type_ref.name),
                        }, value);
                    },
                    else => @panic("todo"),
                    _ => @panic("invalid MemberRef parent table"),
                }
            },
            _ => @panic("invalid custom attr method"),
        }
    }
};

fn decodeCustomAttr(
    name: QualifiedName,
    value: []const u8,
) CustomAttr {
    if (name.eql("System", "FlagsAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .Flags;
    }
    if (name.eql("System", "ObsoleteAttribute")) {
        if (std.mem.eql(u8, value, &[_]u8{ 0, 0 })) {
            return .{ .Obsolete = .{ .Message = null } };
        }
        @panic("TODO: support obsolete with message");
    }

    if (name.eql("System.Runtime.InteropServices", "UnmanagedFunctionPointerAttribute")) {
        // NOTE: 1 fixed arg, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 1, 0, 0, 0, 0, 0 }));
        return .UnmanagedFunctionPointer;
    }

    if (name.eql("System.Diagnostics.CodeAnalysis", "DoesNotReturnAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .DoesNotReturn;
    }

    if (name.eql("Windows.Win32.Interop", "ConstAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .Const;
    }

    if (name.eql("Windows.Win32.Interop", "NotNullTerminatedAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .NotNullTerminated;
    }
    if (name.eql("Windows.Win32.Interop", "NullNullTerminatedAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .NullNullTerminated;
    }

    if (name.eql("Windows.Win32.Interop", "ComOutPtrAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .ComOutPtr;
    }

    if (name.eql("Windows.Win32.Interop", "RetValAttribute")) {
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .RetVal;
    }

    if (name.eql("Windows.Win32.Interop", "FreeWithAttribute")) {
        // 1 fixed arg (string), 0 named args
        const string = decodeString(value);
        return .{ .FreeWith = string.bytes };
    }

    if (name.eql("Windows.Win32.Interop", "MemorySizeAttribute")) {
        // 0 fixed args, 1 named arg
        var it = NamedArgIterator.init(value);
        const arg = it.next() orelse @panic("expected named arg");
        if (!std.mem.eql(u8, arg.name, "BytesParamIndex")) {
            @panic("expected BytesParamIndex named arg");
        }
        if (arg.elem_type != @intFromEnum(winmd.ElementType.i2)) {
            @panic("Expected BytesParamIndex to be of type i2");
        }
        const bytes_param_index = it.readI16(arg.value_offset);
        return .{ .MemorySize = bytes_param_index };
    }

    if (name.eql("Windows.Win32.Interop", "GuidAttribute")) {
        std.debug.assert(value.len == 18);
        std.debug.assert(std.mem.eql(u8, value[16..18], &[_]u8{ 0, 0 }));
        return .{ .Guid = .{
            .Data1 = std.mem.readInt(u32, value[0..4], .little),
            .Data2 = std.mem.readInt(u16, value[4..6], .little),
            .Data3 = std.mem.readInt(u16, value[6..8], .little),
            .Data4 = value[8..16].*,
        } };
    }
    if (name.eql("Windows.Win32.Interop", "PropertyKeyAttribute")) {
        std.debug.assert(value.len == 22);
        std.debug.assert(std.mem.eql(u8, value[20..22], &[_]u8{ 0, 0 }));
        return .{ .PropertyKey = .{
            .guid = .{
                .Data1 = std.mem.readInt(u32, value[0..4], .little),
                .Data2 = std.mem.readInt(u16, value[4..6], .little),
                .Data3 = std.mem.readInt(u16, value[6..8], .little),
                .Data4 = value[8..16].*,
            },
            .pid = std.mem.readInt(u32, value[16..20], .little),
        } };
    }

    if (name.eql("Windows.Win32.Interop", "NativeArrayInfoAttribute")) {
        // 0 fixed args, 2 named args
        var it = NamedArgIterator.init(value);
        // if (it.getNamedArgCount() != 2) {
        //     std.debug.panic("Expected 2 named arguments for NativeArrayInfoAttribute but got {}", .{it.getNamedArgCount()});
        // }

        var count_const: ?i32 = null;
        var count_param_index: ?i16 = null;

        while (it.next()) |arg| {
            if (std.mem.eql(u8, arg.name, "CountConst")) {
                if (arg.elem_type != @intFromEnum(winmd.ElementType.i4)) {
                    @panic("Expected CountConst to be of type i4");
                }
                count_const = it.readI32(arg.value_offset);
            } else if (std.mem.eql(u8, arg.name, "CountParamIndex")) {
                if (arg.elem_type != @intFromEnum(winmd.ElementType.i2)) {
                    @panic("Expected CountParamIndex to be of type i2");
                }
                count_param_index = it.readI16(arg.value_offset);
            } else {
                @panic("Unexpected named argument for NativeArrayInfoAttribute");
            }
        }

        return .{ .NativeArray = .{
            .CountConst = count_const orelse -1,
            .CountParamIndex = count_param_index orelse -1,
        } };
    }

    if (name.eql("Windows.Win32.Interop", "RAIIFreeAttribute")) {
        // 1 fixed arg (string), 0 named args
        const string = decodeString(value);
        std.debug.assert(std.mem.eql(u8, value[string.end..], &[_]u8{ 0, 0 }));
        return .{ .RaiiFree = string.bytes };
    }

    if (name.eql("Windows.Win32.Interop", "NativeTypedefAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .NativeTypedef;
    }

    if (name.eql("Windows.Win32.Interop", "AlsoUsableForAttribute")) {
        // 1 fixed arg (string), 0 named args
        const string = decodeString(value);
        std.debug.assert(std.mem.eql(u8, value[string.end..], &[_]u8{ 0, 0 }));
        return .{ .AlsoUsableFor = string.bytes };
    }

    if (name.eql("Windows.Win32.Interop", "SupportedOSPlatformAttribute")) {
        // 1 fixed arg (string), 0 named args
        const string = decodeString(value);
        std.debug.assert(std.mem.eql(u8, value[string.end..], &[_]u8{ 0, 0 }));
        return .{ .SupportedOSPlatform = string.bytes };
    }

    if (name.eql("Windows.Win32.Interop", "SupportedArchitectureAttribute")) {
        // 1 fixed arg (enum), 0 named args
        std.debug.assert(value.len == 6);
        std.debug.assert(std.mem.eql(u8, value[4..], &[_]u8{ 0, 0 }));
        const int = std.mem.readInt(u32, value[0..4], .little);
        const arches: Architectures = @bitCast(int);
        std.debug.assert(arches.reserved == 0);
        return .{ .SupportedArchitecture = arches };
    }

    if (name.eql("Windows.Win32.Interop", "ScopedEnumAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .ScopedEnum;
    }

    if (name.eql("Windows.Win32.Interop", "DoNotReleaseAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .DoNotRelease;
    }

    if (name.eql("Windows.Win32.Interop", "ReservedAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .Reserved;
    }

    if (name.eql("Windows.Win32.Interop", "InvalidHandleValueAttribute")) {
        // 1 fixed arg (u64), 0 named args
        std.debug.assert(value.len == 10);
        std.debug.assert(std.mem.eql(u8, value[8..], &[_]u8{ 0, 0 }));
        return .{ .InvalidHandleValue = std.mem.readInt(u64, value[0..8], .little) };
    }

    if (name.eql("Windows.Win32.Interop", "AgileAttribute")) {
        // NOTE: 0 fixed args, 0 named args
        std.debug.assert(std.mem.eql(u8, value, &[_]u8{ 0, 0 }));
        return .Agile;
    }

    std.debug.panic(
        "TODO: decode CustomAttr Namespace='{s}' Name='{s}' Value({} bytes)={x}",
        .{
            name.namespace,
            name.name,
            value.len,
            value,
        },
    );
}

fn decodeString(value: []const u8) struct { bytes: []const u8, end: usize } {
    std.debug.assert(value.len >= 1);
    const unsigned_len: usize = @intFromEnum(winmd.decodeSigUnsignedLen(value[0]));
    const string_len = winmd.decodeSigUnsigned(value[0..unsigned_len]);
    const remaining = value[unsigned_len..];
    std.debug.assert(remaining.len >= string_len);
    return .{ .bytes = remaining[0..string_len], .end = unsigned_len + string_len };
}

const QualifiedName = struct {
    namespace: []const u8,
    name: []const u8,
    pub fn eql(self: QualifiedName, namespace: []const u8, name: []const u8) bool {
        return std.mem.eql(u8, self.namespace, namespace) and
            std.mem.eql(u8, self.name, name);
    }
};

const TypeDefOrRef = struct {
    table: enum { TypeDef, TypeRef },
    index: u32,
};
fn fmtTypeDefOrRef(md: *const Metadata, api_name: []const u8, t: TypeDefOrRef) FmtTypeDefOrRef {
    return .{ .md = md, .api_name = api_name, .type = t };
}
const FmtTypeDefOrRef = struct {
    md: *const Metadata,
    api_name: []const u8,
    type: TypeDefOrRef,
    pub fn format(self: FmtTypeDefOrRef, writer: *std.Io.Writer) error{WriteFailed}!void {
        const name, const namespace, const target: TypeRefTarget = blk: switch (self.type.table) {
            .TypeDef => {
                const type_def = self.md.tables.row(.TypeDef, self.type.index);
                break :blk .{
                    self.md.getString(type_def.name),
                    self.md.getString(type_def.namespace),
                    .{ .api = .{ .kind = .initTypeDef(self.md, self.type.index), .parents = .none } },
                };
            },
            .TypeRef => {
                const type_ref = self.md.tables.row(.TypeRef, self.type.index);
                break :blk .{
                    self.md.getString(type_ref.name),
                    self.md.getString(type_ref.namespace),
                    .init(self.md, self.type.index),
                };
            },
        };

        switch (target) {
            .guid => _ = try writeNative(writer, "Guid"),
            .missing => |m| try writer.print(
                "{{\"Kind\":\"MissingClrType\",\"Name\":\"{s}\",\"Namespace\":\"{s}\"}}",
                .{ m.name, m.namespace },
            ),
            .api => |api| {
                // if (std.mem.eql(u8, namespace, "System")) {
                //     if (std.mem.eql(u8, name, "Guid"))
                //         return try writer.writeAll("\"Guid\"");
                //     std.debug.panic("unsupported System type '{s}'", .{name});
                // }
                const api_name = blk: {
                    // Empty namespace means it's a nested type in the current API
                    if (std.mem.eql(u8, namespace, "")) break :blk self.api_name;
                    if (std.mem.startsWith(u8, namespace, shared_namespace_prefix)) break :blk apiFromNamespace(namespace);
                    std.debug.panic(
                        "Unexpected Namespace '{s}' (is not nested and does not start with '{s}') for type '{s}'",
                        .{ namespace, shared_namespace_prefix, name },
                    );
                };
                try writeApiRef(writer, .{
                    .md = self.md,
                    .name = name,
                    .target_kind = api.kind,
                    .api = api_name,
                    .parents = &api.parents,
                });
            },
        }
    }
};

fn fmtTypeJson(
    md: *const Metadata,
    api_name: []const u8,
    sig: []const u8,
) FmtTypeJson {
    return .{ .md = md, .api_name = api_name, .sig = sig };
}
const FmtTypeJson = struct {
    md: *const Metadata,
    api_name: []const u8,
    sig: []const u8,
    pub fn format(self: FmtTypeJson, writer: *std.Io.Writer) error{WriteFailed}!void {
        const consumed = writeTypeJson(
            writer,
            self.md,
            self.api_name,
            self.sig,
        ) catch |err| switch (err) {
            error.SigTruncated, error.InvalidSig => std.debug.panic(
                "invalid signature 0x{x}",
                .{self.sig},
            ),
            else => |e| return e,
        };
        if (consumed != self.sig.len) std.debug.panic(
            "writeTypeJson did not consume entire signature: consumed {} of {}",
            .{ consumed, self.sig.len },
        );
    }
};

fn writeNative(writer: *std.Io.Writer, name: []const u8) error{WriteFailed}!usize {
    try writer.print("{{\"Kind\":\"Native\",\"Name\":\"{s}\"}}", .{name});
    return 1;
}

const TargetKind = enum {
    Default,
    FunctionPointer,
    Com,

    pub fn initTypeDef(md: *const Metadata, type_def_index: u32) TargetKind {
        const type_def = md.tables.row(.TypeDef, type_def_index);

        const base_type_index = type_def.extends.value() orelse return .Com;
        switch (base_type_index.table) {
            .TypeRef => {},
            else => @panic("unexpected base type table"),
        }
        const base_type_ref = md.tables.row(.TypeRef, base_type_index.index);
        const base_type_qn: QualifiedName = .{
            .namespace = md.getString(base_type_ref.namespace),
            .name = md.getString(base_type_ref.name),
        };
        if (base_type_qn.eql("System", "MulticastDelegate")) return .FunctionPointer;
        return .Default;
    }
};

const Parents = struct {
    count: usize,
    buffer: [max][]const u8,

    const max = 3;
    pub const none: Parents = .{ .count = 0, .buffer = undefined };
    pub fn slice(parents: *const Parents) []const []const u8 {
        return parents.buffer[0..parents.count];
    }
    pub fn append(parents: *Parents, name: []const u8) void {
        if (parents.count == max) @panic("increase Parents.max");
        parents.buffer[parents.count] = name;
        parents.count += 1;
    }
};

fn isKnownMissingClrType(namespace: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, namespace, "Windows.Foundation")) {
        if (std.mem.eql(u8, name, "IPropertyValue")) return true;
    } else if (std.mem.eql(u8, namespace, "Windows.Graphics.Effects")) {
        if (std.mem.eql(u8, name, "IGraphicsEffectSource")) return true;
    } else if (std.mem.eql(u8, namespace, "Windows.UI.Composition")) {
        if (std.mem.eql(u8, name, "ICompositionSurface")) return true;
        if (std.mem.eql(u8, name, "CompositionGraphicsDevice")) return true;
        if (std.mem.eql(u8, name, "CompositionCapabilities")) return true;
    } else if (std.mem.eql(u8, namespace, "Windows.UI.Composition.Desktop")) {
        if (std.mem.eql(u8, name, "DesktopWindowTarget")) return true;
    } else if (std.mem.eql(u8, namespace, "Windows.System")) {
        // Looks like this may be defined in another metadata binary?
        //    https://github.com/microsoft/win32metadata/issues/126
        if (std.mem.eql(u8, name, "DispatcherQueueController")) return true;
    }
    return false;
}

const TypeRefTarget = union(enum) {
    guid,
    missing: struct {
        namespace: []const u8,
        name: []const u8,
    },
    api: struct {
        kind: TargetKind,
        parents: Parents,
    },
    pub fn init(md: *const Metadata, type_ref_index: u32) TypeRefTarget {
        const type_ref = md.tables.row(.TypeRef, type_ref_index);
        const name = md.getString(type_ref.name);
        const namespace = md.getString(type_ref.namespace);
        switch (type_ref.resolution_scope.table) {
            .AssemblyRef => {
                if (std.mem.eql(u8, namespace, "System")) {
                    if (std.mem.eql(u8, name, "Guid")) return .guid;
                }
                if (isKnownMissingClrType(namespace, name)) {
                    return .{ .missing = .{ .namespace = namespace, .name = name } };
                }
            },
            .ModuleRef => {},
            .Module => {
                {
                    const module_index = type_ref.resolution_scope.index.asIndex().?;
                    const module = md.tables.row(.Module, module_index);
                    const module_name = md.getString(module.name);
                    std.debug.assert(std.mem.eql(u8, module_name, "Windows.Win32.winmd"));
                }
                const qn: TypeName = .{ .namespace = type_ref.namespace, .name = type_ref.name };
                var maybe_kind: ?TargetKind = null;
                var it = md.type_map.getIterator(qn);
                while (it.next()) |type_def_index| {
                    const kind: TargetKind = .initTypeDef(md, type_def_index);
                    if (maybe_kind) |old_kind| {
                        std.debug.assert(old_kind == kind);
                    }
                    maybe_kind = kind;
                }
                return .{ .api = .{
                    .kind = maybe_kind orelse std.debug.panic(
                        "TypeRef '{s}:{s}' missing",
                        .{ md.getString(qn.namespace), md.getString(qn.name) },
                    ),
                    .parents = .none,
                } };
            },
            .TypeRef => {
                std.debug.assert(namespace.len == 0);
                const parent_type_ref_index = type_ref.resolution_scope.index.asIndex().?;
                std.debug.assert(parent_type_ref_index != type_ref_index);
                return initNested(md, parent_type_ref_index, name);
            },
        }
        std.debug.panic(
            "unsupported TypeRef '{s}:{s}' (scope {s})",
            .{ namespace, name, @tagName(type_ref.resolution_scope.table) },
        );
    }
    pub fn initNested(
        md: *const Metadata,
        type_ref_index: u32,
        nested_name: []const u8,
    ) TypeRefTarget {
        const type_ref = md.tables.row(.TypeRef, type_ref_index);
        const name = md.getString(type_ref.name);
        const namespace = md.getString(type_ref.namespace);
        switch (type_ref.resolution_scope.table) {
            .AssemblyRef => @panic("unexpected"),
            .ModuleRef => @panic("unexpected"),
            .Module => {
                const qn: TypeName = .{ .namespace = type_ref.namespace, .name = type_ref.name };
                var maybe_kind: ?TargetKind = null;
                var it = md.type_map.getIterator(qn);
                while (it.next()) |type_def_index| {
                    var iterator = md.nested_map.getIterator(type_def_index);
                    while (iterator.next()) |nested_class_index| {
                        const entry = md.tables.row(.NestedClass, nested_class_index);
                        const nested_type_def_index = entry.nested.asIndex().?;
                        const nested_type_def = md.tables.row(.TypeDef, nested_type_def_index);
                        if (std.mem.eql(u8, md.getString(nested_type_def.name), nested_name)) {
                            const kind: TargetKind = .initTypeDef(md, nested_type_def_index);
                            if (maybe_kind) |old_kind| {
                                std.debug.assert(old_kind == kind);
                            }
                            maybe_kind = kind;
                        }
                    }
                }
                return .{ .api = .{
                    .kind = maybe_kind orelse std.debug.panic(
                        "nested type '{s}' is missing from module TypeRef '{s}:{s}'",
                        .{ nested_name, namespace, name },
                    ),
                    .parents = .none,
                } };
            },
            .TypeRef => {
                std.debug.assert(namespace.len == 0);
                const parent_type_ref_index = type_ref.resolution_scope.index.asIndex().?;
                std.debug.assert(parent_type_ref_index != type_ref_index);
                var result = initNested(md, parent_type_ref_index, name);
                switch (result) {
                    .guid, .missing => @panic("invalid"),
                    .api => |*api| {
                        api.parents.append(name);
                        return result;
                    },
                }
            },
        }
    }
};

fn writeApiRef(writer: *std.Io.Writer, args: struct {
    md: *const Metadata,
    name: []const u8,
    target_kind: TargetKind,
    api: []const u8,
    parents: *const Parents,
}) error{WriteFailed}!void {
    try writer.print(
        "{{\"Kind\":\"ApiRef\",\"Name\":\"{s}\",\"TargetKind\":\"{s}\",\"Api\":\"{s}\",\"Parents\":[",
        .{
            args.name,
            @tagName(args.target_kind),
            args.api,
        },
    );
    {
        var sep: FirstOnce("", ",") = .{};
        for (args.parents.slice()) |parent| {
            try writer.print("{s}\"{s}\"", .{ sep.next(), parent });
        }
    }
    try writer.writeAll("]}");
}

// Returns the number of bytes consumed by a type signature
fn countTypeSigBytes(sig: []const u8) !usize {
    if (sig.len == 0) return error.SigTruncated;

    const elem_type = winmd.ElementType.decode(sig[0]) orelse return error.InvalidSig;
    return switch (elem_type) {
        .void, .boolean, .char, .i1, .u1, .i2, .u2, .i4, .u4, .i8, .u8, .r4, .r8, .string, .intptr, .uintptr => 1,
        .ptr, .byref, .szarray => 1 + try countTypeSigBytes(sig[1..]),
        // Valuetype/Class: 1 byte + compressed token
        .valuetype, .class => {
            if (sig.len < 2) return error.SigTruncated;
            const token_len = winmd.decodeSigUnsignedLen(sig[1]);
            return 1 + @intFromEnum(token_len);
        },
        // Array: 1 byte + element type + array shape
        .array => {
            const elem_len = try countTypeSigBytes(sig[1..]);
            var offset: usize = 1 + elem_len;
            if (offset + 2 > sig.len) return error.SigTruncated;

            // Skip: Rank (1 byte), NumSizes (1 byte), Sizes (compressed ints), NumLoBounds (1 byte), LoBounds (compressed ints)
            offset += 1; // Rank
            const num_sizes = sig[offset];
            offset += 1;

            // Skip sizes
            for (0..num_sizes) |_| {
                if (offset >= sig.len) return error.SigTruncated;
                const size_len = winmd.decodeSigUnsignedLen(sig[offset]);
                offset += @intFromEnum(size_len);
            }

            // Skip NumLoBounds and LoBounds
            if (offset >= sig.len) return error.SigTruncated;
            const num_lo_bounds = sig[offset];
            offset += 1;

            for (0..num_lo_bounds) |_| {
                if (offset >= sig.len) return error.SigTruncated;
                const lo_bound_len = winmd.decodeSigUnsignedLen(sig[offset]);
                offset += @intFromEnum(lo_bound_len);
            }

            return offset;
        },

        else => @panic("countTypeSigBytes: unsupported type"),
    };
}

fn writeTypeJson(
    writer: *std.Io.Writer,
    md: *const Metadata,
    api_name: []const u8,
    sig: []const u8,
) error{ WriteFailed, SigTruncated, InvalidSig }!usize {
    if (sig.len == 0) return error.SigTruncated;

    return switch (winmd.ElementType.decode(sig[0]) orelse return error.InvalidSig) {
        .end => @panic("todo"),
        .void => return try writeNative(writer, "Void"),
        .boolean => return try writeNative(writer, "Boolean"),
        .char => return try writeNative(writer, "Char"),
        .i1 => return try writeNative(writer, "SByte"),
        .u1 => return try writeNative(writer, "Byte"),
        .i2 => return try writeNative(writer, "Int16"),
        .u2 => return try writeNative(writer, "UInt16"),
        .i4 => return try writeNative(writer, "Int32"),
        .u4 => return try writeNative(writer, "UInt32"),
        .i8 => return try writeNative(writer, "Int64"),
        .u8 => return try writeNative(writer, "UInt64"),
        .r4 => return try writeNative(writer, "Single"),
        .r8 => return try writeNative(writer, "Double"),
        .string => return try writeNative(writer, "String"),
        .ptr => {
            try writer.writeAll("{\"Kind\":\"PointerTo\",\"Child\":");
            const child_consumed = try writeTypeJson(writer, md, api_name, sig[1..]);
            try writer.writeAll("}");
            return 1 + child_consumed;
        },
        .byref => @panic("todo"),
        .class, .valuetype => {
            const token_bytes = sig[1..];
            if (token_bytes.len == 0) @panic("truncated");
            const token_len = winmd.decodeSigUnsignedLen(token_bytes[0]);
            if (token_bytes.len < token_len.int(usize)) @panic("truncated token");
            const token_encoded: winmd.TypeToken = @enumFromInt(winmd.decodeSigUnsigned(token_bytes[0..token_len.int(usize)]));
            const token = token_encoded.decode() catch @panic("invalid type token");
            try fmtTypeDefOrRef(md, api_name, .{
                .table = switch (token.table) {
                    .TypeDef => .TypeDef,
                    .TypeRef => .TypeRef,
                    .TypeSpec => @panic("TypeSpec unsupported"),
                    _ => @panic("invalid table"),
                },
                .index = token.index,
            }).format(writer);
            return 1 + token_len.int(usize);
        },
        .@"var" => @panic("todo"),
        .array => {
            // Array signature: ARRAY Type ArrayShape
            // ArrayShape: Rank NumSizes Size* NumLoBounds LoBound*

            const elem_type_len = try countTypeSigBytes(sig[1..]);
            const shape_start = 1 + elem_type_len;

            if (shape_start + 3 > sig.len) return error.SigTruncated;

            const rank = sig[shape_start];
            _ = rank; // unused for now
            const num_sizes = sig[shape_start + 1];

            if (num_sizes != 1) @panic("expected num_sizes==1");
            var offset = shape_start + 2; // After rank and numsizes
            if (offset >= sig.len) return error.SigTruncated;
            const size_len = winmd.decodeSigUnsignedLen(sig[offset]);
            const size = winmd.decodeSigUnsigned(sig[offset..][0..@intFromEnum(size_len)]);
            offset += @intFromEnum(size_len);

            // skip NumLoBounds and LoBounds
            if (offset >= sig.len) return error.SigTruncated;
            const num_lo_bounds = sig[offset];
            offset += 1;
            for (0..num_lo_bounds) |_| {
                if (offset >= sig.len) return error.SigTruncated;
                const lo_bound_len = winmd.decodeSigUnsignedLen(sig[offset]);
                offset += @intFromEnum(lo_bound_len);
            }

            try writer.writeAll("{\"Kind\":\"Array\",\"Shape\":");
            if (size == 1) {
                try writer.writeAll("null");
            } else {
                try writer.print("{{\"Size\":{}}}", .{size});
            }
            try writer.writeAll(",\"Child\":");
            {
                const check = try writeTypeJson(writer, md, api_name, sig[1..]);
                std.debug.assert(check == elem_type_len);
            }
            try writer.writeAll("}");
            return offset;
        },
        .genericinst => @panic("todo"),
        .typed_byref => @panic("todo"),
        .intptr => return try writeNative(writer, "IntPtr"),
        .uintptr => return try writeNative(writer, "UIntPtr"),
        .fnptr => @panic("todo"),
        .object => @panic("todo"),
        .szarray => @panic("todo"),
        .mvar => @panic("todo"),
    };
}

fn fmtValueTypeJson(@"type": u8) FmtValueTypeJson {
    return .{ .type = @"type" };
}
const FmtValueTypeJson = struct {
    type: u8,
    pub fn format(self: FmtValueTypeJson, writer: *std.Io.Writer) error{WriteFailed}!void {
        switch (winmd.ElementType.decode(self.type) orelse @panic("invalid type byte")) {
            //.void => try writer.writeAll("\"Void\""),
            // .boolean => try writer.writeAll("\"Boolean\""),
            // .char => try writer.writeAll("\"Char\""),
            .i1 => try writer.writeAll("\"SByte\""),
            .u1 => try writer.writeAll("\"Byte\""),
            .i2 => try writer.writeAll("\"Int16\""),
            .u2 => try writer.writeAll("\"UInt16\""),
            .i4 => try writer.writeAll("\"Int32\""),
            .u4 => try writer.writeAll("\"UInt32\""),
            .i8 => try writer.writeAll("\"Int64\""),
            .u8 => try writer.writeAll("\"UInt64\""),
            .r4 => try writer.writeAll("\"Single\""),
            .r8 => try writer.writeAll("\"Double\""),
            .string => try writer.writeAll("\"String\""),
            else => |t| std.debug.panic("todo: support value type '{s}'", .{@tagName(t)}),
        }
    }
};

const Metadata = struct {
    tables: *const winmd.Tables,
    string_heap: ?[]const u8,
    blob_heap: ?[]const u8,

    type_map: TypeMap,
    interface_map: winmd.Map(.InterfaceImpl),
    constant_map: winmd.Map(.Constant),
    layout_map: winmd.Map(.ClassLayout),
    custom_attr_map: winmd.Map(.CustomAttr),
    nested_map: winmd.Map(.NestedClass),
    impl_map_map: winmd.Map(.ImplMap),

    fn getString(md: *const Metadata, index: winmd.StringHeapIndex) [:0]const u8 {
        return winmd.getString(md.string_heap, index) orelse std.debug.panic(
            "invalid string heap index {}",
            .{index},
        );
    }
    fn getBlob(md: *const Metadata, index: winmd.BlobHeapIndex) []const u8 {
        return winmd.getBlob(md.blob_heap, index) orelse std.debug.panic(
            "invalid blob heap index {}",
            .{index},
        );
    }
};

const TypeName = struct {
    namespace: winmd.StringHeapIndex,
    name: winmd.StringHeapIndex,
};

pub const TypeMap = struct {
    links: []const winmd.OptionalIndex(u32),
    map: std.AutoHashMapUnmanaged(TypeName, u32),
    pub fn init(
        allocator: std.mem.Allocator,
        tables: *const winmd.Tables,
    ) error{OutOfMemory}!TypeMap {
        const links = try allocator.alloc(winmd.OptionalIndex(u32), tables.row_counts.TypeDef);
        errdefer allocator.free(links);

        var map: std.AutoHashMapUnmanaged(TypeName, u32) = .{};
        errdefer map.deinit(allocator);

        for (0..tables.row_counts.TypeDef) |i| {
            const type_def = tables.row(.TypeDef, i);
            if (type_def.attributes.visibility.isNested()) {
                links[i] = .none;
            } else {
                const entry = map.getOrPut(allocator, .{
                    .namespace = type_def.namespace,
                    .name = type_def.name,
                }) catch |e| oom(e);
                links[i] = if (entry.found_existing) .fromIndex(entry.value_ptr.*) else .none;
                entry.value_ptr.* = @intCast(i);
            }
        }
        return .{ .links = links, .map = map };
    }
    pub fn deinit(self: *TypeMap, allocator: std.mem.Allocator) void {
        self.map.deinit(allocator);
        allocator.free(self.links);
        self.* = undefined;
    }
    pub fn getIterator(self: *const TypeMap, n: TypeName) winmd.LinkIterator {
        return .{
            .links = self.links,
            .index = if (self.map.get(n)) |i| .fromIndex(i) else .none,
        };
    }
};

const NamedArgIterator = struct {
    value: []const u8,
    offset: usize,

    pub fn init(value: []const u8) NamedArgIterator {
        // Value has prolog already stripped
        // Format: u16 NumNamed, then named args
        // We start at offset 2 to skip the NumNamed count
        return .{
            .value = value,
            .offset = if (value.len >= 2) 2 else 0,
        };
    }

    pub fn getNamedArgCount(self: *const NamedArgIterator) u16 {
        if (self.value.len < 2) return 0;
        return std.mem.readInt(u16, self.value[0..2], .little);
    }

    // Returns a struct with decoded named argument info
    pub fn next(self: *NamedArgIterator) ?struct {
        is_field: bool,
        elem_type: u8,
        name: []const u8,
        value_offset: usize,
    } {
        if (self.offset >= self.value.len) return null;

        // Each named arg starts with a byte indicating field (0x53) or property (0x54)
        const field_or_prop = self.value[self.offset];
        self.offset += 1;

        if (field_or_prop != 0x53 and field_or_prop != 0x54) {
            @panic("Invalid field/property marker in named argument");
        }

        // Next byte is the element type
        if (self.offset >= self.value.len) @panic("Truncated named argument");
        const elem_type = self.value[self.offset];
        self.offset += 1;

        // Decode the name (compressed string)
        if (self.offset >= self.value.len) @panic("Truncated named argument name");
        const string_result = decodeString(self.value[self.offset..]);
        const name = string_result.bytes;
        self.offset += string_result.end;

        // Store current offset for value access
        const value_offset = self.offset;

        // Advance offset based on element type
        switch (winmd.ElementType.decode(elem_type) orelse @panic("Invalid element type")) {
            .boolean => self.offset += 1,
            .char => self.offset += 2,
            .i1, .u1 => self.offset += 1,
            .i2, .u2 => self.offset += 2,
            .i4, .u4 => self.offset += 4,
            .i8, .u8 => self.offset += 8,
            .r4 => self.offset += 4,
            .r8 => self.offset += 8,
            .string => {
                if (self.offset >= self.value.len) @panic("Truncated string value");
                if (self.value[self.offset] == 0xFF) {
                    // null string
                    self.offset += 1;
                } else {
                    const str_result = decodeString(self.value[self.offset..]);
                    self.offset += str_result.end;
                }
            },
            inline else => |t| @panic(std.fmt.comptimePrint("Unsupported element type for named argument: {t}", .{t})),
        }

        return .{
            .is_field = field_or_prop == 0x53,
            .elem_type = elem_type,
            .name = name,
            .value_offset = value_offset,
        };
    }

    // Helper methods to read values of specific types
    pub fn readBool(self: *const NamedArgIterator, offset: usize) bool {
        return self.value[offset] != 0;
    }

    pub fn readI8(self: *const NamedArgIterator, offset: usize) i8 {
        return @bitCast(self.value[offset]);
    }

    pub fn readU8(self: *const NamedArgIterator, offset: usize) u8 {
        return self.value[offset];
    }

    pub fn readI16(self: *const NamedArgIterator, offset: usize) i16 {
        return std.mem.readInt(i16, self.value[offset..][0..2], .little);
    }

    pub fn readU16(self: *const NamedArgIterator, offset: usize) u16 {
        return std.mem.readInt(u16, self.value[offset..][0..2], .little);
    }

    pub fn readI32(self: *const NamedArgIterator, offset: usize) i32 {
        return std.mem.readInt(i32, self.value[offset..][0..4], .little);
    }

    pub fn readU32(self: *const NamedArgIterator, offset: usize) u32 {
        return std.mem.readInt(u32, self.value[offset..][0..4], .little);
    }

    pub fn readI64(self: *const NamedArgIterator, offset: usize) i64 {
        return std.mem.readInt(i64, self.value[offset..][0..8], .little);
    }

    pub fn readU64(self: *const NamedArgIterator, offset: usize) u64 {
        return std.mem.readInt(u64, self.value[offset..][0..8], .little);
    }

    pub fn readF32(self: *const NamedArgIterator, offset: usize) f32 {
        const bits = std.mem.readInt(u32, self.value[offset..][0..4], .little);
        return @bitCast(bits);
    }

    pub fn readF64(self: *const NamedArgIterator, offset: usize) f64 {
        const bits = std.mem.readInt(u64, self.value[offset..][0..8], .little);
        return @bitCast(bits);
    }

    pub fn readString(self: *const NamedArgIterator, offset: usize) ?[]const u8 {
        if (self.value[offset] == 0xFF) return null;
        const str_result = decodeString(self.value[offset..]);
        return str_result.bytes;
    }
};

const Context = struct {
    api: ?[]const u8 = null,
    type: ?[]const u8 = null,
    func: ?[]const u8 = null,
    param: ?[]const u8 = null,

    pub const Kind = enum { api, type, func, param };

    fn equals(context: *Context, comptime kind: Kind, value: ?[]const u8) bool {
        return std.meta.eql(@field(context, @tagName(kind)), value);
    }

    pub fn set(context: *Context, comptime kind: Kind, value: []const u8) void {
        std.debug.assert(context.equals(kind, null));
        @field(context, @tagName(kind)) = value;
        std.debug.assert(context.equals(kind, value));
    }
    pub fn unset(context: *Context, comptime kind: Kind, value: []const u8) void {
        std.debug.assert(context.equals(kind, value));
        @field(context, @tagName(kind)) = null;
        std.debug.assert(context.equals(kind, null));
    }

    pub fn logErrorPrefix(context: *Context) void {
        if (context.api) |api| {
            std.log.err("  current api '{s}'", .{api});
        }
        if (context.type) |t| {
            std.log.err("  current type '{s}'", .{t});
        }
        if (context.func) |f| {
            std.log.err("  current function '{s}'", .{f});
        }
    }
};

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    global.context.logErrorPrefix();
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

pub fn oom(e: error{OutOfMemory}) noreturn {
    @panic(@errorName(e));
}

const std = @import("std");
const winmd = @import("winmd");
const patch = @import("patch.zig");
