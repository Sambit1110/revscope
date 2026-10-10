/* Revscope benchmark: nested calls and recursion.
 * Compiled only to be analyzed; never run. */
#define KEEP __attribute__((noinline, used))

KEEP int leaf(int x) { return x * 3; }
KEEP int middle(int x) { return leaf(x) + 1; }
KEEP int top(int x) { return middle(x) - 2; }
KEEP int factorial(int n) { return n <= 1 ? 1 : n * factorial(n - 1); }
KEEP int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
KEEP int is_odd(int n);
KEEP int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }
KEEP int is_odd(int n) { return n == 0 ? 0 : is_even(n - 1); }

int main(int argc, char **argv) {
    (void)argv;
    return top(argc) + factorial(argc) + fib(argc) + is_even(argc);
}
