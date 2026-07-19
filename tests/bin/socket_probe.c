#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("%d\n", errno);
    } else {
        close(fd);
        printf("0\n");
    }
    return 0;
}
