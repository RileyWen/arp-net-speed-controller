#ifndef ARP_SPOOFER_SEMAPHORE_H
#define ARP_SPOOFER_SEMAPHORE_H

#include <mutex>
#include <condition_variable>

class Semaphore {
public:
    explicit Semaphore(int count_ = 0)
            : count(count_) {}

    void notify();

    void wait();

private:
    std::mutex mtx;
    std::condition_variable cv;
    int count;
};

#endif
