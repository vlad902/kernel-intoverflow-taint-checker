// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.taint -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

void fget_locked(void *fdp, int fd);
long fuword(void *);
void *kmalloc(size_t, int);

///////// Taint sources

void copyin_functions() {
  int i1, i2;

  copyin(NULL, &i1, sizeof(i1));
  memcpy(NULL, NULL, i1); // expected-warning{{Untrusted data is used to specify the buffer size}}

  copy_from_user(&i2, NULL, sizeof(i2));
  memcpy(NULL, NULL, i2); // expected-warning{{Untrusted data is used to specify the buffer size}}

  memcpy(NULL, NULL, fuword(NULL)); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

void direct_taint(int i) {
  clang_analyzer_taint(&i);
  memcpy(NULL, NULL, i); // expected-warning{{Untrusted data is used to specify the buffer size}}
}


///////// Taint sinks

void taint_sinks(int i) {
  clang_analyzer_taint(&i);

  memcpy(NULL, NULL, i); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

// The functions check the inputs so the only way it's interesting is if the
// taint sink is reached with a compound statement including taint that might
// mean the value can be overflown. If the use isn't compound it's not reported
// and the value is considered sanitized.
void taint_sinks_if_compound() {
  int i1, i2;
  clang_analyzer_taint(&i1);
  clang_analyzer_taint(&i2);
  kmalloc(i1, 0);
  memcpy(NULL, NULL, i1);
  kmalloc(i2*2, 0); // expected-warning{{Untrusted data is used to specify the buffer size}}

  int j1, j2;
  clang_analyzer_taint(&j1);
  clang_analyzer_taint(&j2);
  copyin(NULL, NULL, j1);
  memcpy(NULL, NULL, j1);
  copyin(NULL, NULL, j2*2); // expected-warning{{Untrusted data is used to specify the buffer size}}

  int k1, k2;
  clang_analyzer_taint(&k1);
  clang_analyzer_taint(&k2);
  copy_from_user(NULL, NULL, k1);
  memcpy(NULL, NULL, k1);
  copy_from_user(NULL, NULL, k2*2); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

void taint_sinks_if_compound2() {
  int i;
  clang_analyzer_taint(&i);
  kmalloc(i - 2, 0); // expected-warning{{Untrusted data is used to specify the buffer size}}
  kmalloc(i * 2, 0); // expected-warning{{Untrusted data is used to specify the buffer size}}
  kmalloc(i << 2, 0); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

///////// Taint sanitizers

void __fget_locked(int i) {
  clang_analyzer_taint(&i);
  fget_locked(NULL, i);
  memcpy(NULL, NULL, i);
}

int __chk_range_not_ok(unsigned long, unsigned long, unsigned long);
void check_range(int i) {
  clang_analyzer_taint(&i);
  __chk_range_not_ok(0, i, 0);
  memcpy(NULL, NULL, i);
}
