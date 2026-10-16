// ============================================================================
// KLCDS — eBPF Probe: execve tracepoint
// ============================================================================
// This probe attaches to the sys_enter_execve tracepoint and captures:
//   - PID, PPID, UID, GID
//   - comm (task name)
//   - filename (path being executed)
//
// Events are sent to user space via a BPF ring buffer.
//
// Compile with:
//   clang -O2 -g -target bpf -c klcds_probes.c -o klcds_probes.o
//
// Kernel requirements:
//   - Linux 5.8+ (ring buffer support)
//   - CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
//   - CAP_BPF + CAP_PERFMON (or root)
//
// This is the PHASE 2 implementation stub.  The full C code with all probes
// will be built in Phase 2 using libbpf's skeleton (bpftool gen skeleton).
// ============================================================================

#ifndef KLCDS_PROBES_H
#define KLCDS_PROBES_H

// Maximum string length we capture from the kernel
#define MAX_FILENAME_LEN  256
#define MAX_COMM_LEN       16
#define TASK_COMM_LEN      16

// ---------------------------------------------------------------------------
// Event structure shared between BPF (kernel) and Python (user space)
// ---------------------------------------------------------------------------
// This struct is passed through the ring buffer.  Python's ctypes module
// mirrors this layout exactly for zero-copy deserialization.
//
// Design note: we use a single struct with a `syscall_type` discriminator
// rather than separate structs per probe, because:
//   1. One ring buffer, one consumer loop — simpler code
//   2. The union of all fields is ~384 bytes — fits in one ring buffer page
//   3. Python can dispatch on `syscall_type` and ignore irrelevant fields
// ---------------------------------------------------------------------------

struct klcds_event {
    // --- Header (always set) ---
    __u32 syscall_type;              // SyscallType enum (see models.py)
    __u64 timestamp_ns;              // ktime_get_boot_ns()
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];       // bpf_get_current_comm()
    __s32 return_code;               // Syscall return value (from exit probe)

    // --- File context ---
    char  filename[MAX_FILENAME_LEN]; // execve: path, openat: pathname, etc.
    char  filename2[MAX_FILENAME_LEN]; // rename: destination path

    // --- Network context ---
    __u32 src_ip;                     // IPv4 in network byte order
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;                   // IPPROTO_TCP / IPPROTO_UDP

    // --- Module context ---
    char  module_name[64];            // init_module / delete_module

    // --- Privilege context ---
    __u32 target_uid;                 // setuid target
    __u32 target_gid;                 // setgid target
};

#endif // KLCDS_PROBES_H

// ============================================================================
// PROBE IMPLEMENTATIONS (Phase 2)
// ============================================================================
// The following probes will be implemented in Phase 2:
//
// 1. tracepoint/syscalls/sys_enter_execve
//    → Captures process execution with full path
//
// 2. tracepoint/syscalls/sys_enter_openat
//    → Captures file opens (read/write/create)
//
// 3. tracepoint/syscalls/sys_enter_unlink(at)
//    → Captures file deletions
//
// 4. tracepoint/syscalls/sys_enter_rename(at)
//    → Captures file renames (critical for ransomware detection)
//
// 5. tracepoint/syscalls/sys_enter_connect
//    → Captures outbound network connections
//
// 6. tracepoint/syscalls/sys_enter_bind
//    → Captures listening sockets
//
// 7. kprobe/__x64_sys_setuid / kprobe/__x64_sys_setgid
//    → Captures privilege escalation attempts
//
// 8. kprobe/__x64_sys_init_module / kprobe/__x64_sys_finit_module
//    → Captures kernel module loading (rootkit detection)
//
// 9. kprobe/__x64_sys_delete_module
//    → Captures kernel module removal
//
// Each probe fills the relevant fields in klcds_event and submits it
// to the ring buffer via bpf_ringbuf_submit().
// ============================================================================
