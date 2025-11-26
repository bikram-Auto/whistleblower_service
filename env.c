#include "env.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_ENV_VARS 64
#define MAX_KEY 128
#define MAX_VAL 512

static char keys[MAX_ENV_VARS][MAX_KEY];
static char vals[MAX_ENV_VARS][MAX_VAL];
static int env_count = 0;

// Trim whitespace and quotes
static void trim(char *s) {
    // leading
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    // trailing
    int len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len-1])) s[--len] = 0;

    // remove surrounding quotes
    if (s[0] == '"' && s[len-1] == '"' && len > 1) {
        s[len-1] = 0;
        memmove(s, s+1, len - 1);
    }
}

void load_env_file(const char *path) {
    env_count = 0;
    FILE *f = fopen(path ? path : ".env", "r");
    if (!f) return;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        // remove newline
        line[strcspn(line, "\r\n")] = 0;

        // skip comments & empty lines
        if (line[0] == '#' || strlen(line) < 3) continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = 0;
        char *k = line;
        char *v = eq + 1;

        trim(k);
        trim(v);

        if (strlen(k) == 0) continue;

        strncpy(keys[env_count], k, MAX_KEY - 1);
        strncpy(vals[env_count], v, MAX_VAL - 1);

        env_count++;
        if (env_count >= MAX_ENV_VARS) break;
    }

    fclose(f);
}

const char *get_env_value(const char *key) {
    for (int i = 0; i < env_count; i++) {
        if (strcmp(keys[i], key) == 0)
            return vals[i];
    }
    return "";
}
