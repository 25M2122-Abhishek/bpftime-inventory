#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Target process started.\n");
    while (1) {
        printf("Doing some work...\n");
        sleep(1);
    }
    return 0;
}