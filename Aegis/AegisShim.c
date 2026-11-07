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

        // 遍历 load commands 时必须限制在 sizeofcmds 之内，
        // 否则遇到畸形 Mach-O 会越界读导致崩溃
        const uint8_t *p = (const uint8_t *)(h64 + 1);
        const uint8_t *limit = p + h64->sizeofcmds;

        for (uint32_t c = 0; c < h64->ncmds; c++) {
            if (p + sizeof(struct load_command) > limit) break;

            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize < sizeof(struct load_command)) break;   // 畸形 cmdsize

            if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                uintptr_t start = (uintptr_t)(seg->vmaddr + slide);
                uintptr_t end = start + seg->vmsize;
                if (addr >= start && addr < end) return true;
            }

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

        // size 为 0 时 address 不会前进，会死循环
        if (size == 0) break;
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

int aegis_list_process_names(char *out, size_t outSize) {
    if (!out || outSize == 0) return 0;
    out[0] = '\0';

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    // KERN_PROC_ALL 存在经典竞态：查完长度后进程表可能又变了，
    // 第二次 sysctl 会返回 ENOMEM。这里预留 25% 余量并最多重试 3 次。
    struct kinfo_proc *procs = NULL;
    size_t len = 0;

    for (int attempt = 0; attempt < 3; attempt++) {
        size_t probe = 0;
        if (sysctl(mib, 4, NULL, &probe, NULL, 0) != 0 || probe == 0) continue;

        probe += probe / 4;           // 25% 余量
        struct kinfo_proc *buf = (struct kinfo_proc *)malloc(probe);
        if (!buf) continue;

        len = probe;
        if (sysctl(mib, 4, buf, &len, NULL, 0) == 0) {
            procs = buf;
            break;
        }
        free(buf);                    // 失败就放掉，下一轮重来
    }

    if (!procs) return 0;

    int count = (int)(len / sizeof(struct kinfo_proc));
    size_t written = 0;

    for (int i = 0; i < count; i++) {
        const char *name = procs[i].kp_proc.p_comm;
        if (name[0] == '\0') continue;
        size_t l = strlen(name);
        if (written + l + 2 >= outSize) break;
        memcpy(out + written, name, l);
        written += l;
        out[written++] = '\n';
    }
    free(procs);

    out[written] = '\0';
    return (int)written;
}


// ===== 新增：挂载点与映像分析 =====

/// 根文件系统是否可写（正常 iOS 应为只读）
bool aegis_root_writable(void) {
    struct statfs sfs;
    if (statfs("/", &sfs) != 0) return false;
    return (sfs.f_flags & MNT_RDONLY) == 0;
}

/// 返回指定挂载点的 flags，成功写入 *outFlags 返回 true
bool aegis_mount_flags(const char *path, uint32_t *outFlags) {
    if (!path || !outFlags) return false;
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return false;
    *outFlags = sfs.f_flags;
    return true;
}

/// 取指定索引映像的 mach header 地址
void *aegis_dyld_image_header(int index) {
    uint32_t count = _dyld_image_count();
    if (index < 0 || (uint32_t)index >= count) return NULL;
    return (void *)_dyld_get_image_header((uint32_t)index);
}

/// 统计挂载点总数
int aegis_mount_count(void) {
    int n = getfsstat(NULL, 0, MNT_NOWAIT);
    return n > 0 ? n : 0;
}


// ===== 自身 Mach-O 分析 =====

/// 遍历主程序（image 0）的 load commands，把 LC_LOAD_DYLIB 的路径写入 out（换行分隔）
int aegis_self_load_dylibs(char *out, size_t outSize) {
    if (!out || outSize == 0) return 0;
    out[0] = '\0';

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!hdr || hdr->magic != MH_MAGIC_64) return 0;

    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *limit = p + hdr->sizeofcmds;
    size_t written = 0;
    int n = 0;

    for (uint32_t c = 0; c < hdr->ncmds; c++) {
        if (p + sizeof(struct load_command) > limit) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) break;

        if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            const char *name = (const char *)lc + dc->dylib.name.offset;
            size_t len = strnlen(name, lc->cmdsize);
            if (len > 0 && written + len + 2 < outSize) {
                memcpy(out + written, name, len);
                written += len;
                out[written++] = '\n';
                n++;
            }
        }
        p += lc->cmdsize;
    }
    out[written] = '\0';
    return n;
}

/// 主程序 Mach-O 的 sizeofcmds 与 ncmds，用于和 dyld 视图对比
bool aegis_self_header_info(uint32_t *outNcmds, uint32_t *outSizeofcmds) {
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!hdr || hdr->magic != MH_MAGIC_64) return false;
    if (outNcmds) *outNcmds = hdr->ncmds;
    if (outSizeofcmds) *outSizeofcmds = hdr->sizeofcmds;
    return true;
}


/// 读取主程序 Mach-O 的 LC_ENCRYPTION_INFO_64 cryptid
/// cryptid = 1 表示加密（App Store 分发），0 表示未加密（自签名/越狱部署）
bool aegis_self_cryptid(uint32_t *outCryptid) {
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!hdr || hdr->magic != MH_MAGIC_64) return false;

    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *limit = p + hdr->sizeofcmds;

    for (uint32_t c = 0; c < hdr->ncmds; c++) {
        if (p + sizeof(struct load_command) > limit) break;
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) break;

        if (lc->cmd == LC_ENCRYPTION_INFO_64 &&
            lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *ei =
                (const struct encryption_info_command_64 *)lc;
            if (outCryptid) *outCryptid = ei->cryptid;
            return true;
        }
        p += lc->cmdsize;
    }
    return false;
}
