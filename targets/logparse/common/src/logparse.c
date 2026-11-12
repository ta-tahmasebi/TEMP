#include <stdio.h>
#include <string.h>

#define MAX_MESSAGE 31
#define LINE_SIZE 256

int store_message(char *destination, const char *source, char separator);

/* Validate a supported log level. */
static int valid_level(const char *level)
{
    return strcmp(level, "INFO") == 0 || strcmp(level, "WARN") == 0 ||
           strcmp(level, "ERROR") == 0;
}

/* Parse and normalize one log record. */
int main(void)
{
    char line[LINE_SIZE];
    char message[MAX_MESSAGE + 1];

    if (fgets(line, sizeof(line), stdin) == NULL) {
        fprintf(stderr, "error: empty input\n");
        return 2;
    }
    line[strcspn(line, "\n")] = '\0';

    char *pipe = strchr(line, '|');
    char *colon = strchr(line, ':');
    char *separator = pipe == NULL ? colon :
                      (colon == NULL || pipe < colon ? pipe : colon);
    if (separator == NULL) {
        fprintf(stderr, "error: missing separator\n");
        return 2;
    }

    char separator_value = *separator;
    *separator = '\0';
    if (!valid_level(line)) {
        fprintf(stderr, "error: invalid level\n");
        return 2;
    }
    if (store_message(message, separator + 1, separator_value) != 0) {
        fprintf(stderr, "error: message too long\n");
        return 2;
    }

    printf("[%s] %s\n", line, message);
    return 0;
}
