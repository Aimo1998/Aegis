//
//  AegisShim.c
//  Aegis
//
//  底层系统调用包装：绕开 libc/Objective-C 层，拿到"另一条路"的结果用于交叉验证。
//

#include "AegisShim.h"

#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

// 不同 iOS SDK 版本可能未导出这些宏，做一层兜底
#ifndef SYS_lstat
#define SYS_lstat 190
#endif
#ifndef SYS_stat
#define SYS_stat 188
#endif

#pragma mark - 原始 syscall 封装

int aegis_raw_lstat(const char *path, void *statBuf) {
    // 直接下 syscall，绕过 libc 的 lstat 符号（可能被 fishhook 替换）
    return (int)syscall(SYS_lstat, path, statBuf);
}

int aegis_raw_stat(const char *path, void *statBuf) {
    return (int)syscall(SYS_stat, path, statBuf);
}

int aegis_csops(uint32_t pid, uint32_t ops, void *useraddr, uint32_t usersize) {
    // csops 没有公开的 libc 包装，必须走 syscall
    // SYS_csops = 169（XNU）
    return (int)syscall(169, pid, ops, useraddr, usersize);
}

#pragma mark - 内核启动参数

bool aegis_read_bootargs(char *buf, size_t bufSize, size_t *outLen) {
    if (!buf || bufSize == 0) return false;
    size_t size = bufSize;
    // 部分越狱会用 sysctl hook 过滤 kern.bootargs，这里直接取原始值
    if (sysctlbyname("kern.bootargs", buf, &size, NULL, 0) != 0) {
        return false;
    }
    if (outLen) *outLen = size;
    return true;
}

#pragma mark - 地址归属判断

bool aegis_address_in_image(uintptr_t addr) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr) continue;

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64 *h64 = (const struct mach_header_64 *)hdr;
        if (h64->magic != MH_MAGIC_64) continue;

        // 粗粒度：用 __TEXT 段范围判断（maxprot 足够做归属检测）
        const uint8_t *p = (const uint8_t *)(h64 + 1);
        for (uint32_t c = 0; c < h64->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                uintptr_t end = start + seg->vmsize;
                if (addr >= start && addr < end) return true;
            }
            if (lc->cmdsize == 0) break;
            p += lc->cmdsize;
        }
    }
    return false;
}

#pragma mark - RWX 内存页统计

int aegis_count_rwx_regions(void) {
    int count = 0;
    vm_address_t address = 0;
    vm_size_t size = 0;

    while (1) {
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName = MACH_PORT_NULL;

        kern_return_t kr = vm_region_64(mach_task_self(),
                                        &address, &size,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info,
                                        &infoCount,
                                        &objectName);
        if (kr != KERN_SUCCESS) break;

        bool w = (info.protection & VM_PROT_WRITE) != 0;
        bool x = (info.protection & VM_PROT_EXECUTE) != 0;

        // 排除 JIT / dyld 正常区域：只看同时 W+X 且不属于已加载映像的页
        if (w && x) {
            if (!aegis_address_in_image((uintptr_t)address)) {
                count++;
            }
        }

        address += size;
        if (address == 0) break;
    }
    return count;
}

#pragma mark - 端口探测

bool aegis_port_open(int port, int timeoutMs) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return r == 0;
}

// iOS SDK 不提供 <sys/ptrace.h>，这里自行声明原型
// 符号本身存在于 libsystem_kernel，链接期可解析
extern int ptrace(int _request, int _pid, void *_addr, int _data);
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

#pragma mark - Swift 不可用符号的封装

int aegis_dyld_image_count(void) {
    return (int)_dyld_image_count();
}

const char *aegis_dyld_image_name(int index) {
    return _dyld_get_image_name((uint32_t)index);
}

int aegis_ptrace_deny_attach(void) {
    return ptrace(PT_DENY_ATTACH, 0, (void *)0, 0);
}

int aegis_fork_raw(void) {
#ifndef SYS_fork
#define SYS_fork 2
#endif
    return (int)syscall(SYS_fork);
}

int aegis_mount_points(char *out, size_t outSize) {
    if (!out || outSize == 0) return 0;
    out[0] = '\0';

    int count = getfsstat(NULL, 0, MNT_NOWAIT);
    if (count <= 0) return 0;

    struct statfs *buf = (struct statfs *)malloc(sizeof(struct statfs) * (size_t)count);
    if (!buf) return 0;

    int n = getfsstat(buf, sizeof(struct statfs) * count, MNT_NOWAIT);
    if (n <= 0) { free(buf); return 0; }

    size_t written = 0;
    for (int i = 0; i < n; i++) {
        const char *p = buf[i].f_mntonname;
        size_t len = strlen(p);
        if (written + len + 2 >= outSize) break;
        memcpy(out + written, p, len);
        written += len;
        out[written++] = '\n';
    }
    free(buf);
    out[written] = '\0';
    return (int)written;
}
