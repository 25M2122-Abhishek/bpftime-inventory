#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "data.h"

void ulog1(data_t* d) {}

int target_func(data_t* d) {
    printf("target_func\n");
    ulog1(d);
    return 0;
}

int main(int argc, char *argv[]) {
    int a = 10, b = 20;
    char str[] = "Hello, eBPF!";
    // char str1[] = "Hello, eBPF!";
    unsigned long len = sizeof(str);
    // char str[64] = "Hello, eBPF!";

    printf("In main program:\n");
    printf("Value of a: %d\n", a);
    // printf("Address of a: %p\n", &a);
    // printf("Address of a: %d\n", (int) &a);
    printf("Value of b: %d\n", b);
    // printf("Address of a: %p\n", &b);
    // printf("Address of a: %d\n", (int) &b);
    printf("Value of str: %s\n", str);
    // printf("Address of str: %p\n", (void *)str);
    printf("Length of str: %lu\n", len);
    printf("====================================================\n");
    
    data_t d = {.a = a, .b = b, .str = str, .len = len};
    // data_t d = { .a = a, .b = b, .str = "Hello, eBPF!" };
    target_func(&d);
    // target_func(&a, &b);
    return 0;
}
