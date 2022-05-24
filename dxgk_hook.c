#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

static int (*real_ioctl)(int fd, unsigned request, void *data);
static int (*real_open)(const char *filename, int flags, ...);

static int g_dxg_fd = -1;

int ioctl(int fd, unsigned request, void *data)
{
	fprintf(stderr, "%s: fd=%d request=%08x data=%p\n",
			__func__, fd, request, data);
	return real_ioctl(fd, request, data);
}

int open(const char *filename, int flags, ...) {
	int ret = -1;
	fprintf(stderr, "%s: filename=%s flags=%d\n", __func__, filename, flags);
	if (!real_open) {
		real_open = dlsym(RTLD_NEXT, "open");
	}
	if (!real_ioctl) {
		real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	}
	ret = real_open(filename, flags);
	if (!strcmp(filename, "/dev/dxg")) {
		g_dxg_fd = ret;
	}
	return ret;
}
