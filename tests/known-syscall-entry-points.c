// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.taint -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

struct syscall_args { int i; };
void freebsd_syscall(struct syscall_args *uap) {
  memcpy(NULL, NULL, uap->i); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

void incorrect_freebsd_syscall_args1(struct syscall_args *not_uap) {
  memcpy(NULL, NULL, not_uap->i);
}

struct wrong_struct_name { int i; };
void incorrect_freebsd_syscall_args2(struct wrong_struct_name *uap) {
  memcpy(NULL, NULL, uap->i);
}

void SYSC_linux_syscall(int i) {
  memcpy(NULL, NULL, i); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

// TODO: XNU
