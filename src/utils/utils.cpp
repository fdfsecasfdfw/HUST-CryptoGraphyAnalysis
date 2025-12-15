#include "utils.h"

#include <functional>
#include <thread>

u16 utils::shiftLeft(const u16 a, const int x)
{
    if (x >= 16 || x <= -16) [[unlikely]]
    {
        return 0;
    }
    if (x > 0)
        return a << x;
    if (x < 0)
        return a >> -x;
    return a;
}

u16 utils::shiftRollLeft(const u16 a, const int x)
{
    const int shift = x & 15;
    if (shift == 0) return a;
    return (a << shift) | (a >> (16 - shift));
}

void utils::multiTask(const std::size_t start, const std::size_t end, const u32 groupNumber,
                      const std::function<void(u64, u64)> &func)
{
    const std::size_t tasksNumber = end - start;
    const std::size_t perGroupTasks = tasksNumber / groupNumber;

    std::vector<std::thread> threads;
    threads.reserve(groupNumber);

    for (int i = 0; i < groupNumber; i++)
        threads.emplace_back(func, i * perGroupTasks, (i + 1) * perGroupTasks);

    for (auto &thread : threads)
        thread.join();
}