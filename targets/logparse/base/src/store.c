#include <stddef.h>

/* Copy a message into the record buffer. */
int store_message(char *destination, const char *source, char separator)
{
    size_t index = 0;
    (void)separator;
    while (source[index] != '\0') {
        destination[index] = source[index];
        index++;
    }
    destination[index] = '\0';
    return 0;
}
