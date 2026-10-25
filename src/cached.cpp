gb_internal GB_COMPARE_PROC(string_cmp) {
	String const &x = *(String *)a;
	String const &y = *(String *)b;
	return string_compare(x, y);
}

// odin_cache_root: $ODIN_CACHE_DIR, one cache for every build. Empty when it
// is not set; the cache then lives in `.odin-cache` beside the output.
gb_internal String odin_cache_root(void) {
	char const *dir = gb_get_env("ODIN_CACHE_DIR", permanent_allocator());
	if (dir && *dir) {
		return make_string_c(dir);
	}
	return {};
}

gb_internal bool recursively_delete_directory(String const &path) {
	gbAllocator ha = heap_allocator();
#if defined(GB_SYSTEM_WINDOWS)
	String pattern = concatenate_strings(ha, path, str_lit("\\*"));
	String16 wpattern = string_to_win32_path(ha, pattern);
	gb_free(ha, pattern.text);

	WIN32_FIND_DATAW data = {};
	HANDLE hfind = FindFirstFileW(cast(wchar_t *)wpattern.text, &data);
	gb_free(ha, wpattern.text);
	if (hfind == INVALID_HANDLE_VALUE) {
		return false;
	}

	bool ok = true;
	do {
		String name = string16_to_string(ha, make_string16_c(cast(u16 *)data.cFileName));
		if (name != "." && name != "..") {
			String child = concatenate3_strings(ha, path, str_lit("\\"), name);
			String16 wchild = string_to_win32_path(ha, child);
			wchar_t *wc = cast(wchar_t *)wchild.text;
			DWORD attributes = data.dwFileAttributes;
			if ((attributes & FILE_ATTRIBUTE_DIRECTORY) && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
				ok = recursively_delete_directory(child);
			} else if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
				ok = RemoveDirectoryW(wc) != 0;
			} else {
				if (attributes & FILE_ATTRIBUTE_READONLY) {
					SetFileAttributesW(wc, attributes & ~FILE_ATTRIBUTE_READONLY);
				}
				ok = DeleteFileW(wc) != 0;
			}
			gb_free(ha, wchild.text);
			gb_free(ha, child.text);
		}
		gb_free(ha, name.text);
	} while (ok && FindNextFileW(hfind, &data));
	if (ok && GetLastError() != ERROR_NO_MORE_FILES) {
		ok = false;
	}
	FindClose(hfind);
	if (!ok) {
		return false;
	}

	String16 wpath = string_to_win32_path(ha, path);
	bool removed = RemoveDirectoryW(cast(wchar_t *)wpath.text) != 0;
	gb_free(ha, wpath.text);
	return removed;
#else
	char *cpath = alloc_cstring(ha, path);
	DIR *dir = opendir(cpath);
	if (dir == nullptr) {
		gb_free(ha, cpath);
		return false;
	}

	bool ok = true;
	while (ok) {
		struct dirent *entry = readdir(dir);
		if (entry == nullptr) {
			break;
		}
		String name = make_string_c(entry->d_name);
		if (name == "." || name == "..") {
			continue;
		}
		String child = concatenate3_strings(ha, path, str_lit("/"), name);
		struct stat s;
		if (lstat(cast(char const *)child.text, &s) != 0) {
			ok = false;
		} else if (S_ISDIR(s.st_mode)) {
			ok = recursively_delete_directory(child);
		} else {
			ok = unlink(cast(char const *)child.text) == 0;
		}
		gb_free(ha, child.text);
	}
	closedir(dir);

	if (ok) {
		ok = rmdir(cpath) == 0;
	}
	gb_free(ha, cpath);
	return ok;
#endif
}

gb_internal bool try_clear_cache(Array<String> const &args) {
	String dir = str_lit(".");
	for (isize i = 2; i < args.count; i++) {
		String arg = args[i];
		String out = {};
		if (string_starts_with(arg, str_lit("-out:")) || string_starts_with(arg, str_lit("-out="))) {
			out = substring(arg, 5, arg.len);
		} else if (string_starts_with(arg, str_lit("--out:")) || string_starts_with(arg, str_lit("--out="))) {
			out = substring(arg, 6, arg.len);
		} else {
			gb_printf_err("Unknown argument for clear-cache: %.*s\n", LIT(arg));
			return false;
		}
		String spelled = path_spelled(permanent_allocator(), out);
		if (spelled.len == 0) {
			gb_printf_err("Invalid -out path %.*s\n", LIT(out));
			return false;
		}
		isize slash = spelled.len;
		while (slash > 0 && spelled[slash-1] != '/') {
			slash--;
		}
		dir = substring(spelled, 0, gb_max(slash-1, 0));
		if (dir.len == 0 || (dir.len == 2 && dir[1] == ':')) {
			dir = substring(spelled, 0, slash);
		}
	}
	String cache_dir = concatenate_strings(permanent_allocator(), dir, str_lit("/.odin-cache"));
	// $ODIN_CACHE_DIR is the cache wherever the output goes.
	String root = odin_cache_root();
	if (root.len != 0) {
		cache_dir = root;
	}
#if defined(GB_SYSTEM_WINDOWS)
	String16 wdir = string_to_win32_path(temporary_allocator(), cache_dir);
	DWORD attributes = GetFileAttributesW(cast(wchar_t *)wdir.text);
	if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		// A link in place of the cache is removed, never followed.
		if (DeleteFileW(cast(wchar_t *)wdir.text)) {
			return true;
		}
		return RemoveDirectoryW(cast(wchar_t *)wdir.text) != 0;
	}
#else
	struct stat st = {};
	char const *dir_c = alloc_cstring(temporary_allocator(), cache_dir);
	if (lstat(dir_c, &st) == 0 && S_ISLNK(st.st_mode)) {
		// A link in place of the cache is removed, never followed.
		return unlink(dir_c) == 0;
	}
#endif
	if (!path_is_directory(cache_dir)) {
		return true;
	}
	return recursively_delete_directory(cache_dir);
}


gb_internal u64 crc64_with_seed(void const *data, isize len, u64 seed) {
	isize remaining;
	u64 result = ~seed;
	u8 const *c = cast(u8 const *)data;
	for (remaining = len; remaining--; c++) {
		result = (result >> 8) ^ (GB__CRC64_TABLE[(result ^ *c) & 0xff]);
	}
	return ~result;
}

gb_internal bool check_if_exists_directory_otherwise_create(String const &str) {
#if defined(GB_SYSTEM_WINDOWS)
	String16 wstr = string_to_win32_path(permanent_allocator(), str);
	wchar_t *wstr_c = alloc_wstring(permanent_allocator(), wstr);
	return CreateDirectoryW(wstr_c, nullptr);
#else
	char const *str_c = alloc_cstring(permanent_allocator(), str);
	if (!gb_file_exists(str_c)) {
		int status = mkdir(str_c, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		return status == 0;
	}
	return false;
#endif
}

// make_directory_recursive creates `path` and any missing parent directories.
gb_internal void make_directory_recursive(String const &path) {
	for (isize i = 1; i <= path.len; i++) {
		if (i == path.len || path[i] == '/' || path[i] == '\\') {
			(void)check_if_exists_directory_otherwise_create(substring(path, 0, i));
		}
	}
}

// cache_temp_path is `path` with a pid suffix, so concurrent compilers never write the same file.
gb_internal String cache_temp_path(String const &path) {
#if defined(GB_SYSTEM_WINDOWS)
	long long pid = cast(long long)GetCurrentProcessId();
#else
	long long pid = cast(long long)getpid();
#endif
	gbString s = gb_string_make_length(permanent_allocator(), path.text, path.len);
	s = gb_string_append_fmt(s, ".%lld.tmp", pid);
	return make_string(cast(u8 *)s, gb_string_length(s));
}

// publish_file replaces `dest` with `tmp`, removing `tmp` on failure.
//
// Cache entries are written through a temp so `dest` never holds a partial file: a truncated
// executable would still satisfy the manifest and be run on every later invocation.
// gb_file_move cannot be used, as link()+unlink() fails when the destination exists.
//
// Each file is atomic, but an entry is several files with no entry-level lock:
// concurrent same-entry builds interleave (last writer wins), do not run them concurrently.
gb_internal bool publish_file(String const &tmp, String const &dest) {
	char const *tmp_c = alloc_cstring(temporary_allocator(), tmp);
#if defined(GB_SYSTEM_WINDOWS)
	// MOVEFILE_REPLACE_EXISTING, so an existing entry is never unlinked before its replacement is
	// in place -- a plain MoveFileW refuses the destination and deleting first opens a window
	// where a concurrent build sees no entry at all.
	String16 wtmp  = string_to_win32_path(temporary_allocator(), tmp);
	String16 wdest = string_to_win32_path(temporary_allocator(), dest);
	if (!MoveFileExW(cast(wchar_t *)wtmp.text, cast(wchar_t *)wdest.text, MOVEFILE_REPLACE_EXISTING)) {
		gb_file_remove(tmp_c);
		return false;
	}
	return true;
#else
	if (rename(tmp_c, alloc_cstring(temporary_allocator(), dest)) != 0) {
		gb_file_remove(tmp_c);
		return false;
	}
	return true;
#endif
}

// Copies through a temporary so `to` never holds a partial file, and so the
// entry and the output never share an inode.
gb_internal bool cache_copy_file_direct(String from, String to);
gb_internal bool cache_copy_file(String from, String to) {
	String tmp = cache_temp_path(to);
	if (!cache_copy_file_direct(from, tmp)) {
		gb_file_remove(alloc_cstring(temporary_allocator(), tmp));
		return false;
	}
	return publish_file(tmp, to);
}

gb_internal bool cache_copy_file_direct(String from, String to) {
#if defined(GB_SYSTEM_WINDOWS)
	String16 wfrom = string_to_win32_path(temporary_allocator(), from);
	String16 wto   = string_to_win32_path(temporary_allocator(), to);
	return CopyFileW(cast(wchar_t *)wfrom.text, cast(wchar_t *)wto.text, false) != 0;
#else
	char const *cfrom = alloc_cstring(temporary_allocator(), from);
	char const *cto   = alloc_cstring(temporary_allocator(), to);
	struct stat s;
	if (stat(cfrom, &s) != 0 || !S_ISREG(s.st_mode)) {
		return false;
	}
	int in = open(cfrom, O_RDONLY);
	if (in < 0) {
		return false;
	}
	int out = open(cto, O_WRONLY|O_CREAT|O_TRUNC, s.st_mode & 07777);
	if (out < 0) {
		close(in);
		return false;
	}
	bool ok = true;
	u8 buf[1<<16];
	for (;;) {
		ssize_t n = read(in, buf, gb_size_of(buf));
		if (n == 0) {
			break;
		}
		if (n < 0) {
			ok = false;
			break;
		}
		for (ssize_t done = 0; done < n; ) {
			ssize_t w = write(out, buf+done, n-done);
			if (w <= 0) {
				ok = false;
				break;
			}
			done += w;
		}
		if (!ok) {
			break;
		}
	}
	if (fchmod(out, s.st_mode & 07777) != 0) {
		ok = false;
	}
	close(in);
	close(out);
	return ok;
#endif
}

gb_internal bool cache_write_file(String path, void const *data, isize size) {
	// Written through a temporary: a manifest is either the old one or the new one.
	String tmp = cache_temp_path(path);
	char const *ctmp = alloc_cstring(temporary_allocator(), tmp);
	gbFile f = {};
	if (gb_file_open_mode(&f, gbFileMode_Write, ctmp) != gbFileError_None) {
		return false;
	}
	bool ok = size == 0 || gb_file_write(&f, data, size);
	gb_file_close(&f);
	if (!ok) {
		gb_file_remove(ctmp);
		return false;
	}
	return publish_file(tmp, path);
}

struct CacheOutput {
	String path;
	String name;
};

gb_internal Array<CacheOutput> cache_outputs(void) {
	auto outputs = array_make<CacheOutput>(temporary_allocator(), 0, 3);
	String output = path_to_string(temporary_allocator(), build_context.build_paths[BuildPath_Output]);
	array_add(&outputs, CacheOutput{output, str_lit("output")});

	Path symbols = build_context.build_paths[BuildPath_Symbols];
	if (build_context.ODIN_DEBUG && symbols.name.len > 0) {
		array_add(&outputs, CacheOutput{path_to_string(temporary_allocator(), symbols), str_lit("symbols")});
	}
	if (build_context.metrics.os == TargetOs_windows && build_context.build_mode == BuildMode_DynamicLibrary) {
		String import_lib = concatenate_strings(temporary_allocator(), remove_extension_from_path(output), str_lit(".lib"));
		array_add(&outputs, CacheOutput{import_lib, str_lit("import_lib")});
	}
	return outputs;
}

gb_internal String cache_stored_output(CacheOutput const &o) {
	return concatenate3_strings(temporary_allocator(), build_context.build_cache_data.cache_dir, str_lit("/"), o.name);
}

gb_internal bool try_copy_executable_to_cache(void) {
	debugf("Cache: try_copy_executable_to_cache\n");

	auto outputs = cache_outputs();
	for (CacheOutput const &o : outputs) {
		if (path_is_directory(o.path)) {
			return false;
		}
	}

	gbString stored = gb_string_make(heap_allocator(), "");
	defer (gb_string_free(stored));
	for (CacheOutput const &o : outputs) {
		FileId id = {};
		if (!path_file_id(o.path, &id)) {
			continue;
		}
		if (!cache_copy_file(o.path, cache_stored_output(o))) {
			return false;
		}
		stored = gb_string_append_fmt(stored, "%td %.*s\n", o.name.len, LIT(o.name));
	}

	String outputs_path = build_context.build_cache_data.outputs_path;
	if (!cache_write_file(outputs_path, stored, gb_string_length(stored))) {
		return false;
	}
	build_context.build_cache_data.copy_already_done = true;
	return true;
}

gb_internal bool cache_read_entry(String *data, String *entry) {
	isize len = 0;
	isize i = 0;
	while (i < data->len && gb_char_is_digit(data->text[i])) {
		len = len*10 + (data->text[i] - '0');
		i++;
	}
	if (i == 0 || i >= data->len || data->text[i] != ' ') {
		return false;
	}
	i++;
	if (len > data->len - i - 1 || data->text[i+len] != '\n') {
		return false;
	}
	*entry = substring(*data, i, i+len);
	*data = substring(*data, i+len+1, data->len);
	return true;
}

gb_internal bool cache_manifest_matches(String path, Array<String> const &entries) {
	gbFileContents fc = gb_file_read_contents(temporary_allocator(), false, alloc_cstring(temporary_allocator(), path));
	if (fc.data == nullptr && fc.size != 0) {
		return false;
	}
	String data = make_string(cast(u8 *)fc.data, fc.size);
	for (String const &expected : entries) {
		String entry = {};
		if (!cache_read_entry(&data, &entry) || entry != expected) {
			return false;
		}
	}
	return data.len == 0;
}

gb_internal bool cache_write_manifest(String path, Array<String> const &entries) {
	gbString s = gb_string_make(heap_allocator(), "");
	defer (gb_string_free(s));
	for (String const &e : entries) {
		// Not one format call: that goes through a fixed 4096-byte buffer, and a
		// longer entry (a large $PATH, a long -define:) would be dropped.
		s = gb_string_append_fmt(s, "%td ", e.len);
		s = gb_string_append_length(s, e.text, e.len);
		s = gb_string_appendc(s, "\n");
	}
	return cache_write_file(path, s, gb_string_length(s));
}

gb_internal bool try_copy_executable_from_cache(void) {
	debugf("Cache: try_copy_executable_from_cache\n");

	auto outputs = cache_outputs();
	gbFileContents fc = gb_file_read_contents(temporary_allocator(), false, alloc_cstring(temporary_allocator(), build_context.build_cache_data.outputs_path));
	if (fc.data == nullptr) {
		return false;
	}
	String data = make_string(cast(u8 *)fc.data, fc.size);
	isize restored = 0;
	while (data.len > 0) {
		String name = {};
		if (!cache_read_entry(&data, &name)) {
			return false;
		}
		bool found = false;
		for (CacheOutput const &o : outputs) {
			if (o.name == name) {
				if (!cache_copy_file(cache_stored_output(o), o.path)) {
					return false;
				}
				found = true;
				restored++;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}
	if (restored == 0) {
		return false;
	}
	build_context.build_cache_data.copy_already_done = true;
	return true;
}


// Static libs, object files and asm are baked into the binary; dynamic libs load at runtime.
gb_internal bool foreign_lib_is_statically_linked(String const &path) {
	if (has_asm_extension(path)) {
		return true;
	}
	String ext = path_extension(path, false);
	return str_eq_ignore_case(ext, "a") || str_eq_ignore_case(ext, "lib") ||
	       str_eq_ignore_case(ext, "o") || str_eq_ignore_case(ext, "obj");
}

gb_internal Array<String> cache_gather_files(Checker *c) {
	Parser *p = c->parser;

	auto files = array_make<String>(heap_allocator());
	for (AstPackage *pkg : p->packages) {
		for (AstFile *f : pkg->files) {
			array_add(&files, f->fullpath);
		}
	}

	#if defined(GB_SYSTEM_WINDOWS)
		if (build_context.has_resource) {
			String res_path = {};
			if (build_context.build_paths[BuildPath_RC].basename == "")  {
				res_path = path_to_string(permanent_allocator(), build_context.build_paths[BuildPath_RES]);
			} else {
				res_path = path_to_string(permanent_allocator(), build_context.build_paths[BuildPath_RC]);
			}
			array_add(&files, res_path);
		}
	#endif

	for (auto const &entry : c->info.load_file_cache) {
		auto *cache = entry.value;
		if (!cache || !cache->exists) {
			continue;
		}
		array_add(&files, cache->path);
	}

	// static foreign libs are baked in, so track them too
	for (Entity *e : c->info.foreign_library_names) {
		if (e->LibraryName.decl == nullptr) {
			continue;
		}
		ast_node(imp, ForeignImportDecl, e->LibraryName.decl);
		for (isize i = 0; i < e->LibraryName.paths.count; i++) {
			String lib = string_trim_whitespace(e->LibraryName.paths[i]);
			if (lib.len == 0 || !foreign_lib_is_statically_linked(lib)) {
				continue;
			}
			// `system:` imports are names, not files
			if (i < imp->filepaths.count) {
				Ast *fp = imp->filepaths[i];
				if (fp->tav.mode == Addressing_Constant &&
				    fp->tav.value().kind == ExactValue_String &&
				    string_starts_with(fp->tav.value().value_string, str_lit("system:"))) {
					continue;
				}
			}
			array_add(&files, lib);
		}
	}

	// The compiler itself is an input: a new one can turn identical sources into a different
	// executable. Its path feeds the cache key, so separate installs (a package manager's, a local
	// build) never evict each other, and its mtime feeds the manifest, so upgrading in place does.
	String exe = odin_exe_path();
	if (exe.len != 0) {
		array_add(&files, exe);
	}

	array_sort(files, string_cmp);

	return files;
}

gb_internal Array<String> cache_file_entries(Array<String> const &files) {
	auto entries = array_make<String>(heap_allocator(), 0, files.count*2);
	for (String const &path : files) {
		u8 digest[16] = {};
		gbFileContents fc = gb_file_read_contents(heap_allocator(), false, alloc_cstring(temporary_allocator(), path));
		md5(fc.data, fc.size, digest);
		gb_file_free_contents(&fc);

		u8 *hex = gb_alloc_array(temporary_allocator(), u8, 32);
		for (isize i = 0; i < 16; i++) {
			hex[2*i+0] = "0123456789abcdef"[digest[i] >> 4];
			hex[2*i+1] = "0123456789abcdef"[digest[i] & 15];
		}
		array_add(&entries, path);
		array_add(&entries, make_string(hex, 32));
	}
	return entries;
}

gb_internal bool cache_arg_is_output_name(String arg) {
	isize i = 0;
	while (i < arg.len && i < 2 && arg[i] == '-') {
		i++;
	}
	if (i == 0) {
		return false;
	}
	isize end = i;
	while (end < arg.len && arg[end] != ':' && arg[end] != '=') {
		end++;
	}
	String name = substring(arg, i, end);
	return name == "out" || name == "pdb-name";
}

gb_internal Array<String> cache_gather_args(Array<String> const &args) {
	bool names_in_output = build_context.ODIN_DEBUG && build_context.metrics.os == TargetOs_windows;
	auto res = array_make<String>(heap_allocator(), 0, args.count);
	for (String const &arg : args) {
		if (names_in_output || !cache_arg_is_output_name(arg)) {
			array_add(&res, arg);
		}
	}
	return res;
}

// Environment variables that can change the executable a build produces.
//
// An allowlist rather than the whole environment: PWD, OLDPWD, SHLVL and _ are all exported by
// ordinary shells, so comparing everything means a `cd` or a subshell is enough to miss the cache.
// These are every variable the compiler reads that reaches the output -- the rest only affect
// diagnostics (TERM, NO_COLOR, ODIN_ERROR_POS_STYLE), temporary files (TMPDIR), or where the cache
// itself lives. Windows SDK/MSVC paths also come from the environment; macOS SDK via xcrun.
gb_global char const *CACHED_ENV_NAMES[] = {
	"DEVELOPER_DIR",
	"INCLUDE",
	"LIB",
	"ODIN_ANDROID_NDK",
	"ODIN_ANDROID_NDK_TOOLCHAIN",
	"ODIN_ANDROID_SDK",
	"ODIN_CLANG_PATH",
	"ODIN_ROOT",
	"PATH",
	"SDKROOT",
	"UniversalCRTSdkDir",
	"VCToolsInstallDir",
	"WindowsSdkBinPath",
	"WindowsSdkDir",
	"WindowsSdkVerBinPath",
	"WindowsSDKLibVersion",
	"WindowsSDKVersion",
};

gb_internal Array<String> cache_gather_envs() {
	auto envs = array_make<String>(heap_allocator(), 0, gb_count_of(CACHED_ENV_NAMES));
	for (char const *name : CACHED_ENV_NAMES) {
		char const *value = gb_get_env(name, temporary_allocator());
		gbString s = gb_string_make(temporary_allocator(), name);
		s = gb_string_appendc(s, "=");
		s = gb_string_appendc(s, value ? value : "");
		array_add(&envs, make_string(cast(u8 *)s, gb_string_length(s)));
	}
	array_sort(envs, string_cmp);
	return envs;
}

// returns false if different, true if it is the same
gb_internal bool try_cached_build(Checker *c, Array<String> const &args) {
	TEMPORARY_ALLOCATOR_GUARD();

	auto files = cache_gather_files(c);
	defer (array_free(&files));
	auto file_entries = cache_file_entries(files);
	defer (array_free(&file_entries));
	auto key_args = cache_gather_args(args);
	defer (array_free(&key_args));
	auto envs = cache_gather_envs();
	defer (array_free(&envs));

	u64 crc = 0;
	for (String const &e : file_entries) {
		crc = crc64_with_seed(e.text, e.len, crc);
	}
	for (String const &a : key_args) {
		crc = crc64_with_seed(a.text, a.len, crc);
	}

	String base_cache_dir = odin_cache_root();
	if (base_cache_dir.len != 0) {
		make_directory_recursive(base_cache_dir);
	} else {
		base_cache_dir = build_context.build_paths[BuildPath_Output].basename;
		base_cache_dir = concatenate_strings(permanent_allocator(), base_cache_dir, str_lit("/.odin-cache"));
		(void)check_if_exists_directory_otherwise_create(base_cache_dir);
	}

	gbString crc_str = gb_string_make_reserve(permanent_allocator(), 16);
	crc_str = gb_string_append_fmt(crc_str, "%016llx", crc);
	String cache_dir    = concatenate3_strings(permanent_allocator(), base_cache_dir, str_lit("/"), make_string_c(crc_str));
	String files_path   = concatenate3_strings(permanent_allocator(), cache_dir, str_lit("/"), str_lit("files.manifest"));
	String args_path    = concatenate3_strings(permanent_allocator(), cache_dir, str_lit("/"), str_lit("args.manifest"));
	String env_path     = concatenate3_strings(permanent_allocator(), cache_dir, str_lit("/"), str_lit("env.manifest"));
	String outputs_path = concatenate3_strings(permanent_allocator(), cache_dir, str_lit("/"), str_lit("outputs.manifest"));

	build_context.build_cache_data.cache_dir    = cache_dir;
	build_context.build_cache_data.files_path   = files_path;
	build_context.build_cache_data.args_path    = args_path;
	build_context.build_cache_data.env_path     = env_path;
	build_context.build_cache_data.outputs_path = outputs_path;

	if (check_if_exists_directory_otherwise_create(cache_dir)) {
		return false;
	}
	// exists already
	if (!cache_manifest_matches(files_path, file_entries)) {
		return false;
	}
	if (!cache_manifest_matches(args_path, key_args)) {
		return false;
	}
	if (!cache_manifest_matches(env_path, envs)) {
		return false;
	}
	return try_copy_executable_from_cache();
}

gb_internal void write_cached_build(Checker *c, Array<String> const &args) {
	TEMPORARY_ALLOCATOR_GUARD();

	auto files = cache_gather_files(c);
	defer (array_free(&files));
	auto file_entries = cache_file_entries(files);
	defer (array_free(&file_entries));
	auto key_args = cache_gather_args(args);
	defer (array_free(&key_args));
	auto envs = cache_gather_envs();
	defer (array_free(&envs));

	debugf("Cache: updating %.*s\n", LIT(build_context.build_cache_data.cache_dir));
	bool ok = cache_write_manifest(build_context.build_cache_data.files_path, file_entries);
	ok = ok && cache_write_manifest(build_context.build_cache_data.args_path, key_args);
	ok = ok && cache_write_manifest(build_context.build_cache_data.env_path, envs);
	if (!ok) {
		gb_file_remove(alloc_cstring(temporary_allocator(), build_context.build_cache_data.files_path));
	}
}
