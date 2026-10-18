#ifndef TAPTUN_POSIX_IO_H
#define TAPTUN_POSIX_IO_H

#include "taptun_api.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/uio.h>
#include <unistd.h>

static inline int taptun_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    if ((flags & O_NONBLOCK) != 0) return 0;
    errno = EINVAL;
    return -1;
}

static inline int taptun_make_pipe(int descriptors[2]) {
    if (pipe(descriptors) != 0) return -1;
    for (int index = 0; index < 2; ++index) {
        int flags = fcntl(descriptors[index], F_GETFL);
        if (flags < 0 || fcntl(descriptors[index], F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(descriptors[index], F_SETFD, FD_CLOEXEC) < 0) {
            int error = errno;
            close(descriptors[0]);
            close(descriptors[1]);
            errno = error;
            return -1;
        }
    }
    return 0;
}

static inline int taptun_make_pipes(int wake[2], int stop[2]) {
    if (taptun_make_pipe(wake) != 0) return -1;
    if (taptun_make_pipe(stop) == 0) return 0;
    int error = errno;
    close(wake[0]);
    close(wake[1]);
    errno = error;
    return -1;
}

static inline void taptun_close_pipes(int wake[2], int stop[2]) {
    close(wake[0]);
    close(wake[1]);
    close(stop[0]);
    close(stop[1]);
}

static inline void taptun_signal(int fd) {
    ssize_t result;
    do {
        result = write(fd, "x", 1);
    } while (result < 0 && errno == EINTR);
    /* EAGAIN means a notification is already pending. */
}

static inline int taptun_wait_io(int fd, short events, int stop_fd) {
    struct pollfd descriptors[2] = { { fd, events, 0 }, { stop_fd, POLLIN, 0 } };
    int result;
    do {
        result = poll(descriptors, 2, -1);
    } while (result < 0 && errno == EINTR);
    if (result < 0) return TAPTUN_ERROR;
    /* The stop pipe stays readable until final Close, waking every waiter. */
    if (descriptors[1].revents != 0) return TAPTUN_ERROR_CLOSED;
    if ((descriptors[0].revents & events) != 0) return TAPTUN_OK;
    errno = EIO;
    return TAPTUN_ERROR;
}

static inline int taptun_writev(int fd, const struct iovec* vectors, int count, int stop_fd) {
    for (;;) {
        ssize_t written = count == 1
            ? write(fd, vectors[0].iov_base, vectors[0].iov_len)
            : writev(fd, vectors, count);
        if (written >= 0) return (int)written;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return TAPTUN_ERROR;
        int result = taptun_wait_io(fd, POLLOUT, stop_fd);
        if (result != TAPTUN_OK) return result;
    }
}

static inline int taptun_write(int fd, const void* data, int size, int stop_fd) {
    struct iovec vector = { (void*)data, (size_t)size };
    return taptun_writev(fd, &vector, 1, stop_fd);
}

#endif
