#pragma once

#include <span>

#include "BlockCipher.hh"
#include "utils.h"

/**
 * @brief 破解第5-8轮算法
 */
template <int rounds>
    requires (rounds >= 5 && rounds <= 8)
class MITM
{
    public:
        /**
         *
         * @param ToVerifyPC 用于验证得到密钥正确性的明密文对
         * @param oracle 加密应答
         * @param threadsNum 默认执行任务的子线程数，确保为2的幂次方
         * @return 恢复的密钥
         */
        static u64 crackCipher(
            std::span<std::pair<u32, u32>> ToVerifyPC,
            const oracle<rounds>& oracle,
            const u32 threadsNum = 16
        )
        {
            u64 key{};
            if constexpr (rounds < 7)
            {
                const u32 cipher = oracle.getCipher(0);
                std::unordered_map<u32, std::vector<u16>> backwardMap;
                std::vector<std::vector<std::pair<u32, u16>>> localMap(threadsNum);
                std::vector<std::pair<u32, u16>> possibleK012;
                std::vector<std::vector<std::pair<u32, u16>>> localPossibleK012(threadsNum);
                thread_local u16 roundKey[rounds];
                for (int i = 0; i < threadsNum; i++)
                    localMap[i].reserve((1ul << 16) / threadsNum);

                //猜测K2，解密cipher到第4轮的中间状态middleState，保存每一对(middleState, k2)
                auto backwardTask = [cipher, &localMap, threadsNum](const u64 start, const u64 end)
                {
                    for (u64 k2 = start; k2 < end; k2++)
                    {
                        BlockCipher::calRoundKey(k2 << 32, roundKey, rounds);
                        const u32 middle = BlockCipher::PartialDecryptWord(cipher, roundKey, rounds, 4);
                        localMap[start * threadsNum / (1ul << 16)].emplace_back(std::make_pair(middle, k2));
                    }
                };
                utils::multiTask(0, 1 << 16, threadsNum, backwardTask);
                for (auto vec : localMap)
                {
                    for (auto& [fst, snd] : vec)
                        backwardMap[fst].emplace_back(snd);
                }

                // 明文输入0x00000000，经过两轮后，可以判断K0的[15, 10, 4]位
                // 会对第二轮的中间状态产生影响，遍历K0有效位和K1
                constexpr u32 MASK_3BIT = 0x4208; // 0100 0010 0000 1000
                auto forwardTask = [&backwardMap, threadsNum, &localPossibleK012](
                    const std::size_t start, const std::size_t end)
                {
                    for (std::size_t s = start; s < end; s++)
                    {
                        const auto s_ = (s >> 3) << 16 | utils::scatter(s & (1 << 3) - 1, MASK_3BIT);
                        BlockCipher::calRoundKey(s_, roundKey, 4);
                        if (u32 _cipher = BlockCipher::EncryptWord(0, roundKey, 4); backwardMap.contains(_cipher))
                        {
                            for (auto v : backwardMap[_cipher])
                            {
                                localPossibleK012[start * threadsNum / (1 << 19)].emplace_back(
                                    std::make_pair(s_, v));
                            }
                        }
                    }
                };
                utils::multiTask(0, 1 << 19, threadsNum, forwardTask);
                for (const auto& vec : localPossibleK012)
                    for (auto& v : vec)
                        possibleK012.emplace_back(v);

                for (int i = 0; i < 1 << 13; ++i)
                {
                    for (auto [key01, key2] : possibleK012)
                    {
                        constexpr u32 MASK_13BIT = 0xbdf7;
                        key = key01 | utils::scatter(i, MASK_13BIT) | static_cast<u64>(key2) << 32;
                        bool allPass{true};
                        for (auto [_plain, _cipher] : ToVerifyPC)
                        {
                            BlockCipher::calRoundKey(key, roundKey, rounds);
                            if (const u32 vCipher = BlockCipher::EncryptWord(_plain, roundKey, rounds); vCipher !=
                                _cipher)
                            {
                                allPass = false;
                                break;
                            }
                        }
                        if (allPass)
                            goto end;
                    }
                }
            }
            else
            {
                // todo
            }
            key = 0;
        end:
            return key;
        }
};