#pragma once

#include <random>
#include <cstdint>
#include <functional>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

class utils
{
    public:
        static uint16_t bitwiseNot(uint16_t x);
        /**
         * @brief 移位函数
         * @param a 操作对象
         * @param x 左移位数，为负数则向右
         * @return 结果
         */
        static uint16_t shiftLeft(uint16_t a, int x);
        /**
         * @brief 循环移位函数
         * @param a 操作对象
         * @param x 左移位数，为负数则向右
         * @return 结果
         */
        static uint16_t shiftRollLeft(uint16_t a, int x);

        static u32 rand32(std::mt19937_64& gen)
        {
            std::uniform_int_distribution<u32> dis(0, std::numeric_limits<u32>::max());
            return dis(gen);
        }

        static u64 rand64(std::mt19937_64& gen)
        {
            std::uniform_int_distribution<u64> dis(0, std::numeric_limits<u64>::max());
            return dis(gen);
        }

        /**
         * 确保groupNumber整除总任务数
         */
        static void multiTask(std::size_t start, std::size_t end, u32 groupNumber, const std::function<void(u64, u64)>& func);
};
