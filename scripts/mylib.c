#include <stdio.h>

__attribute__((constructor))
void init(void) {
    printf("*** LD_PRELOAD ACTIVE ***\n");
}
