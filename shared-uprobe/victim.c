#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int target_func() {
    printf("target_func\n");
    return 0;
}

int main(int argc, char *argv[]) {
    for(int i=0;i<10;i++) {
        sleep(1);
        target_func();
    }
    return 0;
}
