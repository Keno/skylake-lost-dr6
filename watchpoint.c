#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>

__attribute__((format(printf, 1, 2))) inline static int atomic_printf(
    const char* fmt, ...) {
  va_list args;
  char buf[1024];
  int len;

  va_start(args, fmt);
  len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);
  return write(STDOUT_FILENO, buf, len);
}


inline static int check_cond(int cond) {
  if (!cond) {
    atomic_printf("FAILED: errno=%d (%s)\n", errno, strerror(errno));
  }
  return cond;
}

#define test_assert(cond) assert("FAILED: !" && check_cond(cond))

inline static int atomic_puts(const char* str) {
  return atomic_printf("%s\n", str);
}

#define ARRAY_SIZE(a)                               \
  ((sizeof(a) / sizeof(*(a))) /                     \
  !(sizeof(a) % sizeof(*(a))))

struct DebugControl {
  uintptr_t dr0_local : 1;
  uintptr_t dr0_global : 1;
  uintptr_t dr1_local : 1;
  uintptr_t dr1_global : 1;
  uintptr_t dr2_local : 1;
  uintptr_t dr2_global : 1;
  uintptr_t dr3_local : 1;
  uintptr_t dr3_global : 1;

  uintptr_t ignored : 8;

  uintptr_t dr0_type : 2;
  uintptr_t dr0_len : 2;
  uintptr_t dr1_type : 2;
  uintptr_t dr1_len : 2;
  uintptr_t dr2_type : 2;
  uintptr_t dr2_len : 2;
  uintptr_t dr3_type : 2;
  uintptr_t dr3_len : 2;
};

struct PackedDebugControl {
  union {
    struct DebugControl ctrl;
    uintptr_t val;
  };
};

struct test_instance {
  size_t start_offset;
  size_t break_offset;
  size_t end_offset;
};

static void breakpoint(void)
{
  __asm__("int $3");
}

static void do_memset(void *start, size_t n)
{
  uintptr_t a = 0;
  __asm__("rep stosb\n\tint $3\n\t" ::"a"(a), "c"(n), "D"(start));
}

static void cont_wait_stop(pid_t child) {
  int status;
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
}

static void advance_rip(pid_t child) {
  struct user_regs_struct regs;
  struct iovec iov;
  pid_t wret;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  test_assert(0 == ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov));

  regs.rip += 1;
  test_assert(0 == ptrace(PTRACE_SETREGSET, child, (void*)NT_PRSTATUS, &iov));
}

int main(void) {
  pid_t child;
  int status;
  int pipe_fds[2];
  struct test_instance *program;
  size_t nprograms;

  // Setup program
  size_t start_at = 3903;
  nprograms = 0x1000+126;
  program = malloc(nprograms * sizeof(struct test_instance));
  for (int i = start_at; i < nprograms; ++i) {
    program[i].start_offset = 63;
    program[i].break_offset = i;
    program[i].end_offset = 0x1000+126;
  }

  test_assert(0 == pipe(pipe_fds));

  size_t max_size = 0;
  for (int i = start_at; i < nprograms; ++i) {
    size_t n = program[i].end_offset - program[i].start_offset;
    if (n > max_size)
      max_size = n;
  }

  void *ptr = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);

    for (int i = start_at; i < nprograms; ++i) {
      breakpoint();
      do_memset(ptr+program[i].start_offset, program[i].end_offset-program[i].start_offset);
      if (0 != madvise(ptr, 0x2000, MADV_DONTNEED)) {
        return 0x10;
      }
    }

    return 77;
  }

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(1 == write(pipe_fds[1], "x", 1));

  atomic_printf("RDI (Start)\tRDI (data breakpoint)\tRDI (Target)\tDR6\tSkid\n\n");

  for (int i = start_at; i < nprograms; ++i) {
    // Wait till we're stopped at the breakpoint
    cont_wait_stop(child);
    advance_rip(child);

    // Setup watchpoint
    test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                            (void*)offsetof(struct user, u_debugreg[0]),
                            (void*)ptr + program[i].break_offset));

    struct PackedDebugControl ctrl;
    assert(sizeof(struct DebugControl) == sizeof(uintptr_t));
    memset(&ctrl, 0, sizeof(struct PackedDebugControl));
    ctrl.ctrl.dr0_local = 1;
    ctrl.ctrl.dr0_type = 0b11;
    ctrl.ctrl.dr0_len = 0;
    test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                            (void*)offsetof(struct user, u_debugreg[7]),
                            (void*)ctrl.val));

    // Continue to watchpoint
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
    test_assert(child == waitpid(child, &status, 0));

    // Clear watchpoint
    uintptr_t dr6 = ptrace(PTRACE_PEEKUSER, child,
                            (void*)offsetof(struct user, u_debugreg[6]));

    // Read rdi
    struct user_regs_struct regs;
    struct iovec iov;
    pid_t wret;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    test_assert(0 == ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov));
    uintptr_t skid = regs.rdi - program[i].break_offset - (uintptr_t)ptr;
    atomic_printf("%lx\t%lx\t%lx\t%s\t%ld%s\n",
      program[i].start_offset,
      program[i].break_offset,
      program[i].end_offset,
      dr6 ? "YES" : "NO",
      skid,
      skid > 128 ? "!" : "");


    // Clear watchpoint
    test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                            (void*)offsetof(struct user, u_debugreg[7]),
                            (void*)0));
    test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                            (void*)offsetof(struct user, u_debugreg[6]),
                            (void*)0));

    if (dr6) {
      cont_wait_stop(child);
    }
    advance_rip(child);

    //cont_wait_stop(child);
  }

  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
