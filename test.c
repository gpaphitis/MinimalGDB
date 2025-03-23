#include <stdio.h>

void foo(void) {
    fprintf(stderr, "Hello World.\n");
}

int main(int argc, char *argv[]) { 

    foo();
    foo();

    return 1;
}
