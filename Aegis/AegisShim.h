//
//  AegisShim.h
//  Aegis
//
//  Swift 无法直接调用可变参数 syscall()，这里做一层 C 包装。
//

#ifndef AegisShim_h
#define AegisShim_h

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

/// 直接走 SYS_lstat 原始系统调用（绕过 libc 层可能的 Hook）
int aegis_raw_lstat(const char *path, void *statBuf);

/// 直接走 SYS_stat
int aegis_raw_stat(const char *path, void *statBuf);

/// csops：查询进程代码签名状态
int aegis_csops(uint32_t pid, uint32_t ops, void *useraddr, uint32_t usersize);

/// CS_OPS_STATUS
#define AEGIS_CS_OPS_STATUS 0

/// csflags 常量
#define AEGIS_CS_VALID       0x00000001
#define AEGIS_CS_DEBUGGED    0x10000000
#define AEGIS_CS_RESTRICT    0x00000800
#define AEGIS_CS_HARD        0x00000100
#define AEGIS_CS_KILL        0x00000200
#define AEGIS_CS_PLATFORM    0x00000400

/// 读取 kern.bootargs，成功返回 true
bool aegis_read_bootargs(char *buf, size_t bufSize, size_t *outLen);

/// 判断地址是否落在任一已加载映像范围内（用于指针完整性启发式检测）
bool aegis_address_in_image(uintptr_t addr);

/// 统计当前进程 RWX 内存页数量
int aegis_count_rwx_regions(void);

/// 探测本机 TCP 端口是否开放（用于 Frida 27042 检测）
bool aegis_port_open(int port, int timeoutMs);


#pragma mark - 供 Swift 调用的底层封装（Swift 侧这些符号不可用）

/// 已加载映像数量
int aegis_dyld_image_count(void);

/// 第 index 个已加载映像的路径（无则返回 NULL）
const char *aegis_dyld_image_name(int index);

/// 调用 ptrace(PT_DENY_ATTACH,...)，返回原始结果（0 或被 hook）
int aegis_ptrace_deny_attach(void);

/// 通过 SYS_fork 直接创建子进程（Swift 的 fork() 被标 unavailable）
int aegis_fork_raw(void);

/// 取挂载点，写入 out（'\n' 分隔），返回写入字节数
int aegis_mount_points(char *out, size_t outSize);

/// 取全部进程名，写入 out（'\n' 分隔），返回字节数
int aegis_list_process_names(char *out, size_t outSize);

#endif /* AegisShim_h */

