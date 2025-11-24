#ifndef ENV_H
#define ENV_H

void load_env_file(const char *path);
const char *get_env_value(const char *key);

#endif
