/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Sinks: type_overrun_memcpy
 *    GoodSink: Perform the memcpy() and prevent overwriting part of the structure
 *    BadSink : Overwrite part of the structure by incorrectly using the sizeof(struct) in memcpy()
 * Flow Variant: 01 Baseline
 *
 * */

#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

 /* SRC_STR is 32 char long, including the null terminator, for 64-bit architectures */
#define SRC_STR "0123456789abcdef0123456789abcde"

typedef struct _charVoid
{
    char charFirst[16];
    void* voidSecond;
    void* voidThird;
} charVoid;



void bad1()
{
    {
        charVoid structCharVoid;
        structCharVoid.voidSecond = (void*)SRC_STR;
        /* Print the initial block pointed to by structCharVoid.voidSecond */
        printf((char*)structCharVoid.voidSecond);
        /* FLAW: Use the sizeof(structCharVoid) which will overwrite the pointer voidSecond */
        memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid));
        structCharVoid.charFirst[(sizeof(structCharVoid.charFirst) / sizeof(char)) - 1] = '\0'; /* null terminate the string */
        printf((char*)structCharVoid.charFirst);
        printf((char*)structCharVoid.voidSecond);
    }
}




static void good1()
{
    {
        charVoid structCharVoid;
        structCharVoid.voidSecond = (void*)SRC_STR;
        /* Print the initial block pointed to by structCharVoid.voidSecond */
        printf((char*)structCharVoid.voidSecond);
        /* FIX: Use sizeof(structCharVoid.charFirst) to avoid overwriting the pointer voidSecond */
        memcpy(structCharVoid.charFirst, SRC_STR, sizeof(structCharVoid.charFirst));
        structCharVoid.charFirst[(sizeof(structCharVoid.charFirst) / sizeof(char)) - 1] = '\0'; /* null terminate the string */
        printf((char*)structCharVoid.charFirst);
        printf((char*)structCharVoid.voidSecond);
    }
}


int main(int argc, char* argv[])
{
    /* seed randomness */
    srand((unsigned)time(NULL));

    printf("Calling good()...");
    good1();
    

    printf("Calling bad()...");
    bad1();
    printf("Finished bad()");

    return 0;
}

//#endif