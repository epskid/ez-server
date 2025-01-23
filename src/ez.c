#pragma once
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    LOG_LEVEL_NONE,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_TRACE
} LogLevel;

typedef struct {
    LogLevel level;
    FILE *out;
} Log;

Log __ez_log;

void Log_cleanup(void) { fclose(__ez_log.out); }

int Log_initialize(LogLevel level, FILE *out) {
    __ez_log = (Log){.level = level, .out = out};
    atexit(Log_cleanup);
    return 0;
}

#define LOG_FATAL(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out,                                                  \
                "[FATAL ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);       \
    exit(EXIT_FAILURE);
#define LOG_ERROR(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out, "[ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_PERROR(input, ...)                                                 \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out,                                                  \
                "[ERROR] " input ": %s\n" __VA_OPT__(, ) __VA_ARGS__,          \
                strerror(errno));
#define LOG_FATAL_PERROR(input, ...)                                           \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out,                                                  \
                "[FATAL ERROR] " input "%s\n" __VA_OPT__(, ) __VA_ARGS__,      \
                strerror(errno));                                              \
    exit(EXIT_FAILURE);
#define LOG_WARNING(input, ...)                                                \
    if (__ez_log.level >= LOG_LEVEL_WARNING)                                   \
        fprintf(__ez_log.out,                                                  \
                "[WARNING] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_INFO(input, ...)                                                   \
    if (__ez_log.level >= LOG_LEVEL_INFO)                                      \
        fprintf(__ez_log.out, "[INFO] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_DEBUG(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_DEBUG)                                     \
        fprintf(__ez_log.out, "[DEBUG] " input "\n" __VA_OPT__(, ) __VA_ARGS__);

#define BAIL(input, ...)                                                       \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out,                                                  \
                "[ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);             \
    return EXIT_FAILURE;
#define BAIL_PERROR(input, ...)                                                \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        fprintf(__ez_log.out,                                                  \
                "[ERROR] " input "%s\n" __VA_OPT__(, ) __VA_ARGS__,            \
                strerror(errno));                                              \
    return EXIT_FAILURE;

typedef struct {
    void *memory;
    size_t capacity;
    size_t next_offset;
} Arena;

Arena Arena_new(size_t capacity) {
    void *memory = malloc(capacity);
    memset(memory, 0, capacity);
    return (Arena){.memory = memory, .capacity = capacity, .next_offset = 0};
}

void *Arena_allocate(Arena *arena, size_t requested_amount) {
    if (!arena->memory) {
        LOG_ERROR("arena has already been freed");
        raise(SIGTRAP);
        return NULL;
    }

    void *allocated = (char *)arena->memory + arena->next_offset;
    arena->next_offset += requested_amount;

    if (arena->next_offset > arena->capacity) {
        LOG_ERROR("exhausted arena allocation");
        raise(SIGTRAP);
        return NULL;
    }

    return allocated;
}

void Arena_free(Arena *arena) {
    free(arena->memory);
    arena->memory = NULL;
}

typedef struct {
    char *string;
    size_t length;
} String;
