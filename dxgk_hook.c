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
	//fprintf(stderr, "%s: fd=%d request=%08x data=%p\n", __func__, fd, request, data);
    if (fd == g_dxg_fd) {
        dxgk_fuzzer_ioctl(fd, request, data);
    }
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
#include <stdlib.h>
#include <time.h>
#include <linux/ioctl.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#include "/home/alex/Documents/builds/linux/WSL2-Linux-Kernel/include/uapi/misc/d3dkmthk.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define MAX_STORED_SIZE 512
static struct saved_request {
    unsigned request;
    unsigned size;
    unsigned char buffer[MAX_STORED_SIZE];
} saved_requests[LX_IO_MAX + 1] = {
};

static unsigned dxgk_all_ioctls[LX_IO_MAX + 1] = {
    LX_DXOPENADAPTERFROMLUID,
    LX_DXCREATEDEVICE,
    LX_DXCREATECONTEXT,
    LX_DXCREATECONTEXTVIRTUAL,
    LX_DXDESTROYCONTEXT,
    LX_DXCREATEALLOCATION,
    LX_DXCREATEPAGINGQUEUE,
    LX_DXRESERVEGPUVIRTUALADDRESS,
    LX_DXQUERYADAPTERINFO,
    LX_DXQUERYVIDEOMEMORYINFO,
    LX_DXMAKERESIDENT,
    LX_DXMAPGPUVIRTUALADDRESS,
    LX_DXESCAPE,
    LX_DXGETDEVICESTATE,
    LX_DXSUBMITCOMMAND,
    LX_DXCREATESYNCHRONIZATIONOBJECT,
    LX_DXSIGNALSYNCHRONIZATIONOBJECT,
    LX_DXWAITFORSYNCHRONIZATIONOBJECT,
    LX_DXDESTROYALLOCATION2,
    LX_DXENUMADAPTERS2,
    LX_DXCLOSEADAPTER,
    LX_DXCHANGEVIDEOMEMORYRESERVATION,
    LX_DXCREATEHWCONTEXT,
    LX_DXCREATEHWQUEUE,
    LX_DXDESTROYDEVICE,
    LX_DXDESTROYHWCONTEXT,
    LX_DXDESTROYHWQUEUE,
    LX_DXDESTROYPAGINGQUEUE,
    LX_DXDESTROYSYNCHRONIZATIONOBJECT,
    LX_DXEVICT,
    LX_DXFLUSHHEAPTRANSITIONS,
    LX_DXFREEGPUVIRTUALADDRESS,
    LX_DXGETCONTEXTINPROCESSSCHEDULINGPRIORITY,
    LX_DXGETCONTEXTSCHEDULINGPRIORITY,
    LX_DXGETSHAREDRESOURCEADAPTERLUID,
    LX_DXINVALIDATECACHE,
    LX_DXLOCK2,
    LX_DXMARKDEVICEASERROR,
    LX_DXOFFERALLOCATIONS,
    LX_DXOPENRESOURCE,
    LX_DXOPENSYNCHRONIZATIONOBJECT,
    LX_DXQUERYALLOCATIONRESIDENCY,
    LX_DXQUERYRESOURCEINFO,
    LX_DXRECLAIMALLOCATIONS2,
    LX_DXRENDER,
    LX_DXSETALLOCATIONPRIORITY,
    LX_DXSETCONTEXTINPROCESSSCHEDULINGPRIORITY,
    LX_DXSETCONTEXTSCHEDULINGPRIORITY,
    LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMCPU,
    LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU,
    LX_DXSIGNALSYNCHRONIZATIONOBJECTFROMGPU2,
    LX_DXSUBMITCOMMANDTOHWQUEUE,
    LX_DXSUBMITSIGNALSYNCOBJECTSTOHWQUEUE,
    LX_DXSUBMITWAITFORSYNCOBJECTSTOHWQUEUE,
    LX_DXUNLOCK2,
    LX_DXUPDATEALLOCPROPERTY,
    LX_DXUPDATEGPUVIRTUALADDRESS,
    LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU,
    LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU,
    LX_DXGETALLOCATIONPRIORITY,
    LX_DXQUERYCLOCKCALIBRATION,
    LX_DXENUMADAPTERS3,
    LX_DXSHAREOBJECTS,
    LX_DXOPENSYNCOBJECTFROMNTHANDLE2,
    LX_DXQUERYRESOURCEINFOFROMNTHANDLE,
    LX_DXOPENRESOURCEFROMNTHANDLE,
    LX_DXQUERYSTATISTICS,
    LX_DXSHAREOBJECTWITHHOST,
    LX_DXCREATESYNCFILE,
    LX_DXFUZZSENDRAWMSG,
};

static unsigned ioctls_to_ignore[] = {
    //these ones destroy resources
    _IOC_NR(LX_DXDESTROYCONTEXT),
    _IOC_NR(LX_DXDESTROYALLOCATION2),
    _IOC_NR(LX_DXCLOSEADAPTER),
    _IOC_NR(LX_DXDESTROYDEVICE),
    _IOC_NR(LX_DXDESTROYHWCONTEXT),
    _IOC_NR(LX_DXDESTROYHWQUEUE),
    _IOC_NR(LX_DXDESTROYPAGINGQUEUE),
    _IOC_NR(LX_DXDESTROYSYNCHRONIZATIONOBJECT),
    _IOC_NR(LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMCPU),
    _IOC_NR(LX_DXWAITFORSYNCHRONIZATIONOBJECTFROMGPU),
};

static uint32_t cool_word(void)
{
    //TODO: return some handles and pointers
    return rand() % 64;
}

static int dxgk_fuzzer_ioctl(int arg, unsigned request, void *data)
{
	unsigned type = _IOC_TYPE(request);
	unsigned nr = _IOC_NR(request);
    unsigned size = _IOC_SIZE(request);
	//fprintf(stderr, "%s: type=%08x nr=%08x size=%08x\n", __func__, type, nr, size);

    if (nr <= LX_IO_MAX && size <= MAX_STORED_SIZE) {
        saved_requests[nr].request = request;
        saved_requests[nr].size = size;
        memcpy(saved_requests[nr].buffer, data, size);
    }
    
    //let the app initialize the rendering subsystem first
    static unsigned count = 0;
    if (count) {
        srand(time(NULL));
    }
    if (count++ < 100) {
        return -1;
    }

    for (size_t fuzz_attempt = 0; fuzz_attempt < 20; fuzz_attempt++)
    {
        unsigned new_nr = 0;
        while (1) {
            size_t i = 0;
            new_nr = rand() % LX_IO_MAX;
            for (i = 0; i < ARRAY_SIZE(ioctls_to_ignore); i++)
            {
                if (new_nr == ioctls_to_ignore[i]) {
                    break;
                }
            }
            if (i == ARRAY_SIZE(ioctls_to_ignore)) {
                break;
            }
        }
        //fprintf(stderr, "%s:%d new_nr=%08x\n", __func__, __LINE__, new_nr);

        static unsigned char buf[MAX_STORED_SIZE] = {};
        unsigned new_request = saved_requests[new_nr].request;
        size_t new_size = MAX_STORED_SIZE;
        if (!new_request) {
            continue;
            //fprintf(stderr, "%s:%d: saved request NOT found for new_nr=%08x\n", __func__, __LINE__, new_nr);
            //continue;
            new_size = _IOC_SIZE(dxgk_all_ioctls[new_nr]);
            if (new_size > MAX_STORED_SIZE) {
                fprintf(stderr, "%s:%d: new_size=%08zx > %08x\n",
                    __func__, __LINE__, new_size, MAX_STORED_SIZE);
                new_size = MAX_STORED_SIZE;
            }
            new_request = dxgk_all_ioctls[new_nr];
            //new_request = _IOC(_IOC_READ|_IOC_WRITE, 0x47, new_nr, new_size);
            for (size_t idx_u4 = 0; idx_u4 < new_size / 4; idx_u4++) 
            {
                ((uint32_t*)buf)[idx_u4] = cool_word();
            }
        }
        else {
            new_size = saved_requests[new_nr].size;
            memcpy(buf, saved_requests[new_nr].buffer, new_size);
        }
        //fprintf(stderr, "%s:%d: new_nr=%08x new_size=%08zx\n", __func__, __LINE__, new_nr, new_size);
        
        size_t size_in_u4 = new_size / sizeof(uint32_t);
        if (!size_in_u4) {
            continue;
        }
        for (size_t num_corrupt = 0; num_corrupt < 1; num_corrupt++)
        {
            size_t idx_corrupt = rand() % size_in_u4;
            if (idx_corrupt >= size_in_u4) {
                fprintf(stderr, "HMM\n");
                idx_corrupt = size_in_u4 - 1;
            }
            ((uint32_t*)buf)[idx_corrupt] ^= 0x5 << (rand() % 31);
        }

        ioctl(arg, new_request, buf);
    }

	return -1;
}
