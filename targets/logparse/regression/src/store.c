#include <stddef.h>
#include <string.h>

/* Copy a message using an overly strict limit. */
int store_message(char *destination, const char *source, char separator)
{
    size_t index = 0;
    (void)separator;
    if (strlen(source) > 8) {
        return -1;
    }
    while (source[index] != '\0') {
        destination[index] = source[index];
        index++;
    }
    destination[index] = '\0';
    return 0;
}
