#include <string.h>
#include "s2n.h"

/* Return the folder/file of the current context, e.g. `utils/s2n_blob.c` or `extensions/s2n_cert_status.c` */
static inline const char* get_file_and_parent(const char* path) {
    const char* last_sep = strrchr(path, '/');
    if (!last_sep) return path;

    // Find second-to-last separator
    const char* prev_sep = last_sep - 1;
    while (prev_sep > path && *prev_sep != '/') prev_sep--;

    return (prev_sep > path) ? prev_sep + 1 : path;
}

#define S2N_DEBUG_LOGS 1
#define PRINT_BUFFER_SIZE 256

/**
 * Set the logging callback to be used globally across s2n-tls.
 * 
 * We use a global logging function because it's significantly more ergonomic than
 * having to thread a config/connection into every log statement
 */

typedef void (*s2n_log_fn)(const uint8_t message[PRINT_BUFFER_SIZE], const char *module, int line_number, const char* function);
extern s2n_log_fn s2n_global_log;
S2N_API void s2n_set_global_log(s2n_log_fn cb);


#ifdef S2N_DEBUG_LOGS
    #define S2N_DEBUG(...) \
        { \
            uint8_t buffer[PRINT_BUFFER_SIZE] = {0}; \
            int message_length = snprintf((char *)&buffer, PRINT_BUFFER_SIZE, __VA_ARGS__); \
            snprintf((char *)&buffer + message_length, PRINT_BUFFER_SIZE - message_length, "\n"); \
            (*s2n_global_log)(buffer, get_file_and_parent(__FILE__), __LINE__, __func__); \
        };
#else
    #define S2N_DEBUG(...) do {} while (0)
#endif
