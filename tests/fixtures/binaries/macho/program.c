/*
 * Revscope Mach-O test program for the real-engine tests (npm run test:ghidra).
 * The tests compile it with `clang -arch arm64 -O0` into a temporary
 * directory, only so that Revscope can analyze it. It is never run, and the
 * compiled binary is never committed.
 */
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int factorial(int n) {
    int result = 1;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}

static const char *greeting(void) {
    return "hello from revscope";
}

int main(void) {
    puts(greeting());
    return add(factorial(5), 2);
}
