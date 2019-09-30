//
// Created by rileywen on 2019/9/30.
//

#include "concurrent_queue/headers/semaphore.h"

void Semaphore::wait() {
    std::unique_lock<std::mutex> lock(mtx);

    while (count == 0) {
        cv.wait(lock);
    }
    count--;
}

void Semaphore::notify() {
    std::unique_lock<std::mutex> lock(mtx);
    count++;
    cv.notify_one();
}
