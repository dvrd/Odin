#+build linux
package tests_core_os

import "core:os"
import "core:strings"
import "core:sys/linux"
import "core:testing"

// An absolute path is asked of the name, not of the file: the file is not
// opened, so one that cannot be read, or a FIFO with nobody writing to it,
// has an absolute path like any other.
@(test)
absolute_path_does_not_open_the_file :: proc(t: ^testing.T) {
	directory, made := os.make_directory_temp("", "abs-*", context.allocator)
	if !testing.expect_value(t, made, nil) {
		return
	}
	defer delete(directory)
	defer os.remove_all(directory)

	unreadable := strings.concatenate({directory, "/unreadable"})
	defer delete(unreadable)
	fifo := strings.concatenate({directory, "/fifo"})
	defer delete(fifo)

	fd, created := linux.open(strings.clone_to_cstring(unreadable, context.temp_allocator), {.CREAT, .WRONLY}, {})
	testing.expect_value(t, created, linux.Errno.NONE)
	linux.close(fd)
	testing.expect_value(t, linux.mknod(strings.clone_to_cstring(fifo, context.temp_allocator), {.IFIFO, .IRUSR, .IWUSR}, 0), linux.Errno.NONE)

	for name in ([]string{unreadable, fifo}) {
		path, err := os.get_absolute_path(name, context.allocator)
		defer delete(path)
		testing.expect_value(t, err, nil)
		testing.expect(t, strings.has_suffix(path, name[len(directory):]), path)
	}

	// The empty path is the current directory.
	here, here_err := os.get_absolute_path("", context.allocator)
	defer delete(here)
	working, working_err := os.get_working_directory(context.allocator)
	defer delete(working)
	testing.expect_value(t, here_err, nil)
	testing.expect_value(t, working_err, nil)
	testing.expect_value(t, here, working)

	_, missing := os.get_absolute_path(strings.concatenate({directory, "/missing"}, context.temp_allocator), context.allocator)
	testing.expect(t, missing != nil)
}
