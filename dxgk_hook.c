#define _GNU_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

static int (*real_ioctl)(int fd, unsigned request, void *data);
static int (*real_open)(const char *filename, int flags, ...);
static void* (*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

//forward declaration
static int dxgk_fuzzer_ioctl(int arg, unsigned request, void *data);
static void *dxgk_mmap_hook(void *addr, size_t length, int prot, int flags, int fd, off_t offset, void *ret);
static int g_dxg_fd = -1;

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *ret = NULL;
    fprintf(stderr, "%s: addr=%p length=%08zx prot=%08x flags=%08x, fd=%08x, offset=%08zx\n",
        __func__, addr, length, prot, flags, fd, offset);

    ret = real_mmap(addr, length, prot, flags, fd, offset);
    //unfortunately, D3D12 drivers map a huge area and use a custom allocator
    //so we'll have to instead steal valid addresses from IOCTL arguments
    //dxgk_mmap_hook(addr, length, prot, flags, fd, offset, ret);
    return ret;
}

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
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
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

static void dxgk_fuzzer_mutate_ioctls(int arg, unsigned request, void *data)
{
    for (size_t fuzz_attempt = 0; fuzz_attempt < 4; fuzz_attempt++)
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
            //fprintf(stderr, "%s:%d: saved request NOT found for new_nr=%08x\n", __func__, __LINE__, new_nr);
            continue;
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
        fprintf(stderr, "%s:%d: new_nr=%08x new_size=%08zx\n", __func__, __LINE__, new_nr, new_size);
        
        //TODO: for now, just replay already seen ioctls
        //now that we have corrupted shared memory
        #if 0
        size_t size_in_u4 = new_size / sizeof(uint32_t);
        if (!size_in_u4) {
            continue;
        }

        for (size_t num_corrupt = 0; num_corrupt < 10; num_corrupt++)
        {
            size_t idx_corrupt = rand() % size_in_u4;
            if (idx_corrupt >= size_in_u4) {
                fprintf(stderr, "HMM\n");
                idx_corrupt = size_in_u4 - 1;
            }
            if (((uint32_t*)buf)[idx_corrupt]) {
                ((uint32_t*)buf)[idx_corrupt] ^= 0x5 << (rand() % 31);
            }
        }
        #endif

        ioctl(arg, new_request, buf);
    }
}

#define MAX_KNOWN_MEM_RECORDS 128
static struct known_mem_record {
    void *ptr;
    size_t size;
} known_mem[MAX_KNOWN_MEM_RECORDS] = {
};

static void add_mem_record(void *ptr, size_t size)
{
    if (!ptr || !size) {
        return;
    }
    fprintf(stderr, "%s:%d ptr=%p size=%08zx\n",
        __func__, __LINE__, ptr, size);
    for (size_t i = 0; i < ARRAY_SIZE(known_mem); i++)
    {
        if (known_mem[i].ptr == ptr) {
            return;
        }
        if (!known_mem[i].ptr) {
            known_mem[i].ptr = ptr;
            known_mem[i].size = size;
            return;
        }
    }
    fprintf(stderr, "%s:%d: mem table full, replacing random entry\n",
        __func__, __LINE__);
    size_t idx = rand() % ARRAY_SIZE(known_mem);
    known_mem[idx].ptr = ptr;
    known_mem[idx].size = size;
}

static void add_mem_record_u64(size_t addr, size_t size)
{
    add_mem_record((void*)addr, size);
}

static void dxgk_fuzzer_known_mem(int fd, unsigned request, void *data)
{
    switch (request) {
        case LX_DXCREATEDEVICE:
        {
            struct d3dkmt_createdevice *arg = data;
            add_mem_record_u64(arg->command_buffer, arg->command_buffer_size);
            add_mem_record_u64(arg->allocation_list, arg->allocation_list_size);
            add_mem_record_u64(arg->patch_location_list, arg->patch_location_list_size);
        }
        case LX_DXCREATECONTEXT:
        {
            struct d3dkmt_createcontext *arg = data;
            add_mem_record_u64(arg->priv_drv_data, arg->priv_drv_data_size);
            add_mem_record_u64(arg->command_buffer, arg->command_buffer_size);
            add_mem_record_u64(arg->allocation_list, arg->allocation_list_size);
            add_mem_record_u64(arg->patch_location_list, arg->patch_location_list_size);
        }
        case LX_DXCREATECONTEXTVIRTUAL:
        {
            struct d3dkmt_createcontextvirtual *arg = data;
            add_mem_record_u64(arg->priv_drv_data, arg->priv_drv_data_size);
        }
        case LX_DXRENDER:
        {
            struct d3dkmt_render *arg = data;
            add_mem_record_u64(arg->priv_drv_data, arg->priv_drv_data_size);
            add_mem_record_u64(arg->new_command_buffer, arg->new_command_buffer_size);
            add_mem_record_u64(arg->new_allocation_list, arg->new_allocation_list_size);
            add_mem_record_u64(arg->new_patch_pocation_list, arg->new_patch_pocation_list_size);
        }
        default:
            break;
    }
}

static int dxgk_fuzzer_ioctl(int fd, unsigned request, void *data)
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
    dxgk_fuzzer_known_mem(fd, request, data);
    dxgk_fuzzer_mutate_ioctls(fd, request, data);

	return -1;
}

static void *dxgk_mmap_hook(void *addr, size_t length, int prot, int flags,
    int fd, off_t offset, void *ret)
{
    if (!g_dxg_fd) {
        return ret;
    }
    if ((!ret) || ((size_t)ret) == (size_t)-1) {
        return ret;
    }
    switch (length) {
        default:
            return ret;
    }

    fprintf(stderr, "%s: corrupting ret=%p length=%08zx\n",
        __func__, ret, length);
    for (size_t i = 0; i < 10; i++)
    {
        size_t idx_corr = rand() % length;
        idx_corr /= sizeof(uint32_t);
        ((uint32_t*)ret)[idx_corr] ^= 0x5 << (rand() % 31);
    }
    return ret;
}
