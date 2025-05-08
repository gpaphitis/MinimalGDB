#include <stdio.h>

void foo(void)
{
    fprintf(stderr, "Hello World.\n");
}

int main(int argc, char *argv[])
{

    long placemarker = 0xdeadbeef;
    foo();
    foo();
    if (argc > 1)
        printf("%s\n", argv[1]);
    if (argc > 2)
        printf("%s\n", argv[2]);
    if (argc > 3)
        printf("%s\n", argv[3]);
    return 1;
}
