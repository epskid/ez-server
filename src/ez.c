#pragma once
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    LogNone,
    LogError,
    LogWarning,
    LogInfo,
    LogDebug,
    LogTrace
} LogLevel;

typedef struct {
    LogLevel level;
    FILE *out;
} Log;

Log __ez_log;

void Log_cleanup() { fclose(__ez_log.out); }

int Log_initialize(LogLevel level, FILE *out) {
    __ez_log = (Log){.level = level, .out = out};
    atexit(Log_cleanup);
    return 0;
}

#define LOG_FATAL(input)                                                       \
    if (__ez_log.level >= LogError)                                            \
        fprintf(__ez_log.out, "[FATAL ERROR] %s\n", input);                    \
    exit(1);
#define LOG_ERROR(input)                                                       \
    if (__ez_log.level >= LogError)                                            \
        fprintf(__ez_log.out, "[ERROR] %s\n", input);
#define LOG_PERROR(input)                                                      \
    if (__ez_log.level >= LogError)                                            \
        fprintf(__ez_log.out, "[ERROR] %s: %s\n", input, strerror(errno));
#define LOG_FATAL_PERROR(input)                                                \
    if (__ez_log.level >= LogError)                                            \
        fprintf(__ez_log.out, "[FATAL ERROR] %s: %s\n", input,                 \
                strerror(errno));                                              \
    exit(1);
#define LOG_WARNING(input)                                                     \
    if (__ez_log.level >= LogWarning)                                          \
        fprintf(__ez_log.out, "[WARNING] %s\n", input);
#define LOG_INFO(input)                                                        \
    if (__ez_log.level >= LogInfo)                                             \
        fprintf(__ez_log.out, "[INFO] %s\n", input);
#define LOG_DEBUG(input)                                                       \
    if (__ez_log.level >= LogDebug)                                            \
        fprintf(__ez_log.out, "[DEBUG] %s\n", input);
#define LOG_TRACE(input)                                                       \
    if (__ez_log.level >= LogTrace)                                            \
        fprintf(__ez_log.out, "[TRACE] %s\n", input);

#define BAIL(input)                                                            \
    if (__ez_log.level >= LogError)                                            \
        fprintf(__ez_log.out, "[ERROR] %s\n", input);                          \
    exit(1);

typedef struct {
    void *memory;
    size_t capacity;
    size_t next_offset;
} Arena;

Arena Arena_new(size_t capacity) {
    LOG_TRACE("Arena_new()");
    void *memory = malloc(capacity);
    memset(memory, 0, capacity);
    return (Arena){.memory = memory, .capacity = capacity, .next_offset = 0};
}

void *Arena_allocate(Arena *arena, size_t requested_amount) {
    LOG_TRACE("Arena_allocate()");
    if (!arena->memory) {
        LOG_ERROR("arena has already been freed");
        raise(SIGTRAP);
        return NULL;
    }

    void *allocated = arena->memory + arena->next_offset;
    arena->next_offset += requested_amount;

    if (arena->next_offset > arena->capacity) {
        LOG_ERROR("exhausted arena allocation");
        raise(SIGTRAP);
        return NULL;
    }

    return allocated;
}

void Arena_free(Arena *arena) {
    LOG_TRACE("Arena_free()");
    free(arena->memory);
    arena->memory = NULL;
}

typedef struct {
    char *string;
    size_t length;
} String;
