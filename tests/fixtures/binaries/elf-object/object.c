/*
 * Revscope ELF relocatable-object test program for the real-engine tests
 * (npm run test:ghidra). The tests compile it with
 * `clang -target <x86_64|aarch64>-unknown-linux-gnu -c` into a temporary
 * directory, only so that Revscope can analyze it. An object file cannot be
 * run, and it is never committed.
 */
int add(int a, int b) {
    return a + b;
}

int scale(int x) {
    return add(x, x) * 3;
}
