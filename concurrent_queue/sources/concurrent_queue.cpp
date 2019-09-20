#include "concurrent_queue/headers/concurrent_queue.h"

template<typename T>
void concurrent_queue<T>::push_back(T element) {
    scoped_lock lock(m_mtx);

    while (m_size >= m_capacity)
        m_cv_not_full.wait(lock);
    m_q.push(element);

    if (m_size == 0)
        m_cv_not_empty.notify_one();
}

template<typename T>
void concurrent_queue<T>::pop_front() {
    scoped_lock lock(m_mtx);
    if (m_size > 0) {
        m_q.pop();

        if (m_size >= m_capacity)
            m_cv_not_full.notify_one();

        m_size--;
    }
}

template<typename T>
bool concurrent_queue<T>::empty() const {
    scoped_lock lock(m_mtx);
    return m_size == 0;
}

template<typename T>
const T &concurrent_queue<T>::front() const {
    scoped_lock lock(m_mtx);
    if (m_size == 0)
        m_cv_not_full.wait(lock);

    return m_q.front();
}
