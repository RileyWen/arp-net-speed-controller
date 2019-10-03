//
// Created by rileywen on 2019/9/21.
//

#ifndef ARP_SPOOFER_BYTECOUNTER_H
#define ARP_SPOOFER_BYTECOUNTER_H

#include <atomic>
#include <csignal>
#include <unistd.h>
#include <stdio.h>

using std::atomic, std::signal;

class ByteCounter {
public:
    ByteCounter() = delete;

    ~ByteCounter() = delete;

    static void start_counter() {
        ByteCounter::byte_counter = 0;
        alarm(1);
        signal(SIGALRM, ByteCounter::sigalrm_handler);
    }

    static void counter_add(int i) {
        ByteCounter::byte_counter += i;
    }

    static unsigned long get_counter() {
        return ByteCounter::byte_counter;
    }

    static void stop_counter() {
        alarm(0);
    }

    static void sigalrm_handler(int signum) {
        ByteCounter::byte_counter = 0;
        alarm(1);
        signal(SIGALRM, ByteCounter::sigalrm_handler);
    }

private:
    static atomic<unsigned long> byte_counter;
};

#endif //ARP_SPOOFER_BYTECOUNTER_H
