/* Revscope benchmark: loops, conditionals and arithmetic.
 * Compiled only to be analyzed; never run. */
#define KEEP __attribute__((noinline, used))

KEEP int sum_to(int n) {
    int total = 0;
    for (int i = 1; i <= n; i++) total += i;
    return total;
}
KEEP int clamp(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
KEEP unsigned gcd(unsigned a, unsigned b) {
    while (b != 0) {
        unsigned t = a % b;
        a = b;
        b = t;
    }
    return a;
}
KEEP int popcount(unsigned x) {
    int count = 0;
    while (x) {
        count += (int)(x & 1u);
        x >>= 1;
    }
    return count;
}
KEEP int abs_diff(int a, int b) { return a > b ? a - b : b - a; }

int main(int argc, char **argv) {
    (void)argv;
    return sum_to(argc) + clamp(argc, 0, 9) + (int)gcd((unsigned)argc, 12u) + popcount((unsigned)argc) + abs_diff(argc, 7);
}
