#include <stddef.h>
#include <string.h>

/* Guard one message path before copying the value. */
int store_message(char *destination, const char *source, char separator)
{
    size_t index = 0;
    if (separator == '|' && strlen(source) > 31) {
        return -1;
    }
    while (source[index] != '\0') {
        destination[index] = source[index];
        index++;
    }
    destination[index] = '\0';
    return 0;
}
