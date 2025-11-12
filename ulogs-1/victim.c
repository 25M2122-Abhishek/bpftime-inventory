#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int ulog1(int a){}

int target_func(int a) {
    printf("target_func\n");
    ulog1(a);
    return 0;
}

int main(int argc, char *argv[]) {
    int a = 10;
    printf("In main program:\n");
    printf("Value of a: %d\n", a);
    printf("Address of a: %p\n", (void *) &a);
    printf("Address of a: %d\n", (int) &a);
    printf("====================================================\n");
    target_func(a);
    target_func(&a);
    return 0;
}
