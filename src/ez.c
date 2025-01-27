#pragma once
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
pthread_mutex_t __ez_log_mut = PTHREAD_MUTEX_INITIALIZER;

void Log_cleanup(void) {
    fflush(__ez_log.out);
    fclose(__ez_log.out);
}

int Log_initialize(LogLevel level, FILE *out) {
    __ez_log = (Log){.level = level, .out = out};
    atexit(Log_cleanup);
    return 0;
}

#define lfprintf(...)                                                          \
    {                                                                          \
        int __ez_prev_errno = errno;                                           \
        pthread_mutex_lock(&__ez_log_mut);                                     \
        errno = __ez_prev_errno;                                               \
        fprintf(__VA_ARGS__);                                                  \
        pthread_mutex_unlock(&__ez_log_mut);                                   \
    }

#define LOG_FATAL(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[FATAL ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);      \
    exit(EXIT_FAILURE);
#define LOG_ERROR(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_PERROR(input, ...)                                                 \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[ERROR] " input ": %s\n" __VA_OPT__(, ) __VA_ARGS__,         \
                 strerror(errno));
#define LOG_FATAL_PERROR(input, ...)                                           \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[FATAL ERROR] " input ": %s\n" __VA_OPT__(, ) __VA_ARGS__,   \
                 strerror(errno));                                             \
    exit(EXIT_FAILURE);
#define LOG_WARNING(input, ...)                                                \
    if (__ez_log.level >= LOG_LEVEL_WARNING)                                   \
        lfprintf(__ez_log.out,                                                 \
                 "[WARNING] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_INFO(input, ...)                                                   \
    if (__ez_log.level >= LOG_LEVEL_INFO)                                      \
        lfprintf(__ez_log.out, "[INFO] " input "\n" __VA_OPT__(, ) __VA_ARGS__);
#define LOG_DEBUG(input, ...)                                                  \
    if (__ez_log.level >= LOG_LEVEL_DEBUG)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[DEBUG] " input "\n" __VA_OPT__(, ) __VA_ARGS__);

#define BAIL(input, ...)                                                       \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[ERROR] " input "\n" __VA_OPT__(, ) __VA_ARGS__);            \
    return EXIT_FAILURE;
#define BAIL_PERROR(input, ...)                                                \
    if (__ez_log.level >= LOG_LEVEL_ERROR)                                     \
        lfprintf(__ez_log.out,                                                 \
                 "[ERROR] " input ": %s\n" __VA_OPT__(, ) __VA_ARGS__,         \
                 strerror(errno));                                             \
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
    if (arena->memory == NULL) {
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

void *Arena_reallocate(Arena *arena, void *allocated, size_t old_amount,
                       size_t requested_amount) {
    if (old_amount == requested_amount) {
        return arena;
    }

    if ((char *)allocated + old_amount ==
        (char *)arena->memory + arena->next_offset) {
        arena->next_offset += requested_amount;
        return allocated;
    }

    void *new_allocated = Arena_allocate(arena, requested_amount);
    memcpy(new_allocated, allocated, old_amount);

    return new_allocated;
}

void *Arena_strdup(Arena *arena, char *str) {
    char *new_str = Arena_allocate(arena, strlen(str) + 1);
    strcpy(new_str, str);

    return new_str;
}

void Arena_free(Arena *arena) {
    free(arena->memory);
    arena->memory = NULL;
}

typedef struct {
    pthread_t thread;
    atomic_bool running;
    atomic_bool join_now;
} PoolThread;

typedef struct {
    PoolThread *thread;
    int fd;
} PoolThreadParams;

typedef struct {
    void (*task)(void *);
    void *params;
} Task;

void *PoolThread_main(void *params) {
    PoolThreadParams *pt_params = params;
    struct pollfd task_fd = {
        .fd = pt_params->fd, .events = POLLIN, .revents = 0};

    while (!pt_params->thread->join_now) {
        pt_params->thread->running = false;
        while (!pt_params->thread->join_now && (poll(&task_fd, 1, 0) == 0)) {
            sched_yield();
        }
        if (pt_params->thread->join_now) {
            break;
        }
        pt_params->thread->running = true;

        Task *task;
        read(pt_params->fd, &task, sizeof(Task *));
        (task->task)(task->params);
        free(task->params);
        free(task);
    }

    close(pt_params->fd);
    free(pt_params);

    return NULL;
}

void PoolThread_initialize(PoolThread *pool_thread, int task_fd) {
    PoolThreadParams *params = malloc(sizeof(PoolThreadParams));
    params->thread = pool_thread;
    params->fd = task_fd;

    pool_thread->running = false;
    pool_thread->join_now = false;
    pthread_create(&pool_thread->thread, NULL, PoolThread_main, (void *)params);
}

typedef struct {
    PoolThread *threads;
    size_t threads_len;
    int *channels;
} ThreadPool;

ThreadPool *ThreadPool_new(size_t threads_len) {
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    pool->threads_len = threads_len;
    pool->threads = malloc(threads_len * sizeof(PoolThread));
    pool->channels = malloc(threads_len * sizeof(int) * 2);

    for (size_t i = 0; i < threads_len; i++) {
        pipe(pool->channels + (2 * i));
        PoolThread_initialize(&pool->threads[i], pool->channels[(2 * i)]);
    }

    return pool;
}

void ThreadPool_run(ThreadPool *pool, Task *task) {
    for (size_t i = 0; i < pool->threads_len; i++) {
        if (!pool->threads[i].running) {
            write(pool->channels[(2 * i) + 1], &task, sizeof(&task));
            break;
        }
    }
}

void ThreadPool_end(ThreadPool *pool) {
    for (size_t i = 0; i < pool->threads_len; i++) {
        pool->threads[i].join_now = true;
        pthread_join(pool->threads[i].thread, NULL);
        close(pool->channels[(2 * i) + 1]);
    }

    free(pool->threads);
    free(pool->channels);
    free(pool);
}
