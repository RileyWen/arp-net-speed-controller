#ifndef ARP_SPOOFER_CONCURRENT_QUEUE_H
#define ARP_SPOOFER_CONCURRENT_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

using std::mutex, std::scoped_lock, std::condition_variable;
using std::queue;

template<typename T>
class concurrent_queue {
private:
    queue<T> m_q;
    size_t m_size;
    size_t m_capacity;
    mutable mutex m_mtx;
    condition_variable m_cv_not_full;
    condition_variable m_cv_not_empty;

public:
    explicit concurrent_queue(size_t capacity) : m_size(0), m_capacity(capacity) {}

    void push_back(T element);

    void pop_front();

    bool empty() const;

    const T &front() const;
};


#endif //ARP_SPOOFER_CONCURRENT_QUEUE_H
