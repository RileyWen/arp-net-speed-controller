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
    int m_size;
    int m_capacity;
    mutable mutex m_mtx;
    mutable condition_variable m_cv_not_full;
    mutable condition_variable m_cv_not_empty;

public:
    int m_updated_seq;
    static constexpr int DEFAULT_SEQ = -233;

    explicit concurrent_queue(int capacity)
            : m_capacity(capacity), m_size(0), m_updated_seq(DEFAULT_SEQ) {}

    void push_back(const T &element) {
        unique_lock<mutex> lock(m_mtx);

        while (m_size >= m_capacity)
            m_cv_not_full.wait(lock);

        m_q.push(std::move(element));
        m_size++;
        m_updated_seq++;

        lock.unlock();
        m_cv_not_empty.notify_one();
    }

    void push_back(T &&element) {
        unique_lock<mutex> lock(m_mtx);

        while (m_size >= m_capacity)
            m_cv_not_full.wait(lock);

        m_q.push(std::move(element));
        m_size++;
        m_updated_seq++;

        lock.unlock();
        m_cv_not_empty.notify_one();
    }

    T pop_front() {
        unique_lock<mutex> lock(m_mtx);

        while (m_size == 0)
            m_cv_not_empty.wait(lock);

        auto item = m_q.front();
        m_q.pop();
        m_size--;

        lock.unlock();
        m_cv_not_full.notify_one();

        return item;
    }

    queue<T> pop_all() {
        unique_lock<mutex> lock(m_mtx);

        while (m_size == 0)
            m_cv_not_empty.wait(lock);

        auto ret_q = queue<T>();
        std::swap(ret_q, m_q);

        m_size = 0;

        lock.unlock();
        m_cv_not_full.notify_one();

        return ret_q;
    }

    bool empty() const {
        unique_lock<mutex> lock(m_mtx);
        return m_size == 0;
    }
};

#endif
