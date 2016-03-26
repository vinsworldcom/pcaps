#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DGETS_DLL
#include <windows.h>

#include "dgets.h"
#endif

/*
 * dgets() - Dynamic gets
 * 
 * Like fgets() - but dynamic - dgets allows a program to capture 
 * string input of unknown length by dynamically reallocating the 
 * memory capture buffer.  Captures upto provided stop character 
 * or EOF.
 * 
 * INPUT:
 *     FILE * = the file pointer to read from - may be 'stdin'
 *     int    = the size of memory to allocate as needed
 *     char   = character to end on - usually EOF or '\n'
 *              NOTE:  Will always stop if EOF reached.
 * 
 * RETURN:
 *     char * = pointer to the buffer containing the read string
 *              NULL if error
 *
 * EXAMPLE:
 *     ...
 *     #include "dgets.h"
 *     ...
 *     char *str;
 *     if ((str = dgets(stdin, 128, EOF)) == NULL)
 *     {
 *         fprintf(stderr, "Error: dgets()\n");
 *         return 1;
 *     }
 *     printf("%s\n", str);
 *     free(str);
 *
 *     The above code snippet example reads from STDIN, allocating 
 *     128 bytes of memory as needed until an EOF is reached (CTRL-Z 
 *     on Windows, CTRL-D on Unix).  It then prints the string to 
 *     STDOUT and then frees the memory buffer.
 */
#ifdef DGETS_DLL
__declspec(dllexport) char *dgets(FILE *fd, int iAllocSize, char cEnd)
#else
char *dgets(FILE *fd, int iAllocSize, char cEnd)
#endif
{
    int i, iAllocs;
    char *buf, c;

    if (iAllocSize <= 0)
        return '\0';

    iAllocs = 1;
    i = c = 0;

    if ((buf = /*(char *)*/malloc(iAllocSize)) == NULL)
        return '\0';

    while (c != cEnd && c != EOF)
    {
        if (!(c = getc(fd)))
            return '\0';

        if (i >= iAllocSize * iAllocs - 1)
        {
            if ((buf = /*(char *)*/realloc(buf, ++iAllocs * iAllocSize)) == NULL)
                return '\0';
        }
        buf[i++] = c;

        /* 
         * special case:  Cisco's algorithm only works with ASCII 0 - 127
         * if out of that range but not EOF, then exit immediately and caller prints error
         */
        if ((c < 0 || c > 127) && (c != EOF))
            break;
    }
    buf[i] = '\0';
    if ((buf = /*(char *)*/realloc(buf, i + 1)) == NULL)
        return '\0';
    return buf;
}

#ifdef DGETS_DLL
BOOL APIENTRY DllMain(HANDLE hMod, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
#endif

#ifdef TESTING
#include <stdio.h>

#include "dgets.h"

int main(int argc, char* argv[])
{
    char *str;

    printf("Enter string, CTRL-Z (Windows) CTRL-D (*nix) when done:\n");
    if ((str = dgets(stdin, 128, EOF)) == NULL)
    {
        fprintf(stderr, "Error: dgets()\n");
        return 1;
    }
    printf("%s\n", str);
    free(str);

    return 0;
}
#endif
