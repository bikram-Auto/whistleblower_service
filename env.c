#include "env.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ENV_LINE 512
static char secret_value[512] = {0};
static char sender_id_value[128] = {0};

void load_env_file(const char *path) {
    FILE *f = fopen(path ? path : ".env", "r");
    if (!f) return;
    char line[MAX_ENV_LINE];
    while (fgets(line, sizeof(line), f)) {
        // trim newline
        line[strcspn(line, "\r\n")] = 0;
        if (strncmp(line, "SECRET_KEY=", 11) == 0) {
            strncpy(secret_value, line + 11, sizeof(secret_value)-1);
        } else if (strncmp(line, "SENDER_ID=", 10) == 0) {
            strncpy(sender_id_value, line + 10, sizeof(sender_id_value)-1);
        }
    }
    fclose(f);
}

const char *get_env_value(const char *key) {
    if (!key) return "";
    if (strcmp(key, "SECRET_KEY") == 0) return secret_value;
    if (strcmp(key, "SENDER_ID") == 0) return sender_id_value;
    return "";
}
