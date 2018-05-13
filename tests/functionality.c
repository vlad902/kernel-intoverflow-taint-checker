// RUN: %clang_analyze_cc1 -analyzer-checker=core,alpha.security.taint -analyzer-store=region -verify -fno-builtin %s

#include "common.h"

void fixed_size_array_struct_taint() {
  struct {
    int i;
  } s[4];

  copyin(NULL, &s, sizeof(s));

  memcpy(NULL, NULL, s[0].i); // expected-warning{{Untrusted data is used to specify the buffer size}}
  memcpy(NULL, NULL, s[3].i); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

void signed_constraints() {
  int i;
  clang_analyzer_taint(&i);

  memcpy(NULL, NULL, i); // expected-warning{{Untrusted data is used to specify the buffer size}}

  if (i < 0) return;

  memcpy(NULL, NULL, i); // expected-warning{{Untrusted data is used to specify the buffer size}}

  if (i > 128) return;

  memcpy(NULL, NULL, i);
  memcpy(NULL, NULL, i * 2);
}

void and_modulo_constraints() {
  int i;
  clang_analyzer_taint(&i);

  memcpy(NULL, NULL, i & 0xff);
  memcpy(NULL, NULL, i % 0xff);
  memcpy(NULL, NULL, i & 0xffffffff); // expected-warning{{Untrusted data is used to specify the buffer size}}
}

void signedness_shift_contraint() {
  int i;
  clang_analyzer_taint(&i);
  memcpy(NULL, NULL, i >> 20); // expected-warning{{Untrusted data is used to specify the buffer size}}

  unsigned int u;
  clang_analyzer_taint(&u);
  memcpy(NULL, NULL, u >> 20);
}

void comparison_against_symbolic_expression(unsigned int tainted, unsigned int limit) {
  clang_analyzer_taint(&tainted);
  if (tainted > limit)
    return;
  memcpy(NULL, NULL, tainted);
}

void uchar_too_small() {
  unsigned char uc;
  clang_analyzer_taint(&uc);

  memcpy(NULL, NULL, uc);
}

void tainted_func_ptr() {
  struct {
    void (*fp)(void);
  } s;

  copyin(NULL, &s, sizeof(s));
  s.fp(); // expected-warning{{Tainted function pointer}}
}

char array_access(char *foo) {
  int idx;
  clang_analyzer_taint(&idx);

  return foo[idx]; // expected-warning{{Tainted array subscript}}
}

void taint_and_sanitized_propogation() {
  int i;
  clang_analyzer_taint(&i);

  int j = i / 4;
  memcpy(NULL, NULL, j); // expected-warning{{Untrusted data is used to specify the buffer size}}

  if (j < 0 || j > 100)
    return;

  int k = j * 4;
  memcpy(NULL, NULL, k);
}
