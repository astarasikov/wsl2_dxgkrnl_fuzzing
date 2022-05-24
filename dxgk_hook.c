#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

static int (*real_ioctl)(int fd, unsigned request, void *data);
static int (*real_open)(const char *filename, int flags, ...);

//forward declaration
static int dxgk_fuzzer_ioctl(int arg, unsigned request, void *data);
static int g_dxg_fd = -1;

int ioctl(int fd, unsigned request, void *data)
{
	fprintf(stderr, "%s: fd=%d request=%08x data=%p\n",
			__func__, fd, request, data);
	dxgk_fuzzer_ioctl(fd, request, data);
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

//DXGK-specific code
#include <stdint.h>
#include <stdbool.h>
#include <linux/ioctl.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "/home/alex/Documents/builds/linux/WSL2-Linux-Kernel/include/uapi/misc/d3dkmthk.h"
static int dxgk_fuzzer_ioctl(int arg, unsigned request, void *data)
{
	unsigned type = _IOC_TYPE(request);
	fprintf(stderr, "%s: type=%08x\n", __func__, type);
	return -1;
}
