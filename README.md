This clang analyzer checker uses taint analysis to look for integer overflows in various kernels. You can read about it [here](https://tsyrklevich.net/2017/03/27/kernel-clang-analyzer/).

Run FreeBSD/Linux/XNU/Android builds using the same commands as [here](https://github.com/vlad902/kernel-uninitialized-memory-checker) but replace the enabled checker with `alpha.security.taint`. This is not production-worthy code, there is a lot of hacking around ConstraintManager limitations.

To run tests, run `~/build/bin/llvm-lit llvm/tools/clang/test/Analysis/kernel-int-overflow-checker/*.c`
