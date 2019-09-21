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
    size_t m_size;
    size_t m_capacity;
    mutable mutex m_mtx;
    mutable condition_variable m_cv_not_full;
    mutable condition_variable m_cv_not_empty;

public:
    explicit concurrent_queue(size_t capacity) : m_size(0), m_capacity(capacity) {}

    void push_back(T element) {
        unique_lock<mutex> lk(m_mtx);

        while (m_size > m_capacity)
            m_cv_not_full.wait(lk);
        m_q.push(element);

        if (m_size == 0)
            m_cv_not_empty.notify_one();
    }

    void pop_front() {
        unique_lock<mutex> lock(m_mtx);
        if (m_size > 0) {
            m_q.pop();

            if (m_size >= m_capacity)
                m_cv_not_full.notify_one();

            m_size--;
        }
    }

    bool empty() const {
        unique_lock<mutex> lock(m_mtx);
        return m_size == 0;
    }

    const T &front() const {
        unique_lock<mutex> lock(m_mtx);
        while (m_size == 0)
            m_cv_not_full.wait(lock);

        return m_q.front();
    }
};


#endif //ARP_SPOOFER_CONCURRENT_QUEUE_H
