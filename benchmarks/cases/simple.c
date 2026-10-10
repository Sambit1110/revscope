/* Revscope benchmark: simple functions with known names and results.
 * Compiled only to be analyzed; never run. */
#define KEEP __attribute__((noinline, used))

KEEP int add(int a, int b) { return a + b; }
KEEP int sub(int a, int b) { return a - b; }
KEEP int mul_add(int a, int b, int c) { return a * b + c; }
KEEP int identity(int x) { return x; }

int main(int argc, char **argv) {
    (void)argv;
    return add(argc, 2) + sub(argc, 1) + mul_add(argc, 3, 4) + identity(argc);
}
