/* Source for the integration-test fixtures. Rebuild with build_fixtures.sh. */

#include <stdio.h>
#include <string.h>

static const char SECRET[] = "GhidraMCP-fixture-secret";
static const unsigned char MAGIC[8] = {0xde, 0xad, 0xbe, 0xef, 0x13, 0x37, 0xca, 0xfe};

/* Exported on Windows so the PE keeps function names without a PDB. */
#ifdef _WIN32
#define FIXTURE_API __declspec(dllexport) __attribute__((noinline))
#else
#define FIXTURE_API __attribute__((noinline))
#endif

typedef int (*op_fn)(int, int);

FIXTURE_API int add_numbers(int a, int b) {
    return a + b;
}

FIXTURE_API int mul_numbers(int a, int b) {
    return a * b;
}

FIXTURE_API unsigned int checksum(const unsigned char *buf, unsigned int len) {
    unsigned int sum = 0;
    for (unsigned int i = 0; i < len; i++) {
        sum = (sum << 1) ^ buf[i];
    }
    return sum;
}

FIXTURE_API int compute(int x, op_fn op) {
    int total = add_numbers(x, 3);
    total = mul_numbers(total, 2);
    return op(total, x);
}

int main(int argc, char **argv) {
    int result = compute(argc, add_numbers);
    result += (int)checksum(MAGIC, sizeof(MAGIC));
    if (argc > 1 && strcmp(argv[1], SECRET) == 0) {
        puts("unlocked");
    }
    printf("%d\n", result);
    return 0;
}
