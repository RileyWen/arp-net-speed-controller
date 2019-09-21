#ifndef ARP_SPOOFER_CONCURRENT_QUEUE_H
#define ARP_SPOOFER_CONCURRENT_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

using std::mutex, std::unique_lock, std::condition_variable;
using std::queue;

template<typename T>
class concurrent_queue {
private:
    queue<T> m_q;
    mutable mutex m_mtx;
    mutable condition_variable m_cv_not_full;
    mutable condition_variable m_cv_not_empty;

public:
    explicit concurrent_queue() = default;

    void push_back(T element) {
        unique_lock<mutex> lk(m_mtx);

        m_q.push(element);
        lk.unlock();
        m_cv_not_empty.notify_one();
    }

    T pop_front() {
        unique_lock<mutex> lock(m_mtx);

        while (m_q.empty())
            m_cv_not_empty.wait(lock);

        auto item = m_q.front();
        m_q.pop();
        return item;
    }
};


#endif //ARP_SPOOFER_CONCURRENT_QUEUE_H
