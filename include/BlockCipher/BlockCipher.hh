/**
 * @file BlockCipher.hh
 * @brief 提供分组密码的实现工具类
 * @author xw
 */

#pragma once

#include <span>
#include <stdexcept>

#include "utils.h"

class BlockCipher
{
    public:
        /**
         * 密钥编排算法，根据密钥生成轮密钥
         * @param key 密钥
         * @param roundKey 轮密钥存放数组
         * @param round 轮数
         */
        static void calRoundKey(const u64 key, std::span<u16> roundKey, const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");

            const u16 k[4] = {
                static_cast<u16>(key & 0xffff),
                static_cast<u16>((key >> 16) & 0xffff),
                static_cast<u16>((key >> 32) & 0xffff),
                static_cast<u16>((key >> 48) & 0xffff)
            };

            for (int i = 0; i < round; ++i)
            {
                u16 kt;
                if (i < 8)
                    kt = k[i / 2];
                else
                    kt = roundKey[2 * (i / 2) - 7] ^ static_cast<u16>(i / 2 - 4);

                roundKey[i] = i % 2 ? ~kt : kt;
            }
        }

        static u16 SBox(const u16 x) { return ((x << 2) & (x << 1)) xor x; }

        static u16 Permute(const u16 x) { return utils::shiftRollLeft(x, 3) xor utils::shiftRollLeft(x, 9) xor utils::shiftRollLeft(x, 14); }

        static u32 Round(const u32 word, const u16 roundKey, const int current_round)
        {
            u16 L = (word >> 16) & 0xffff, R = word & 0xffff;
            const u16 L_ = L;
            const u16 R_ = R;
            const u16 idx = current_round - 1;

            u16 T = (roundKey & L) xor R xor idx;
            T = SBox(T);
            T = Permute(T);
            L = R_ xor (roundKey & T);
            R = L_ xor T;
            return static_cast<u32>(L) << 16 | R;
        }

        static u32 InverseRound(const u32 word, const u16 roundKey, const int current_round)
        {
            u16 L = (word >> 16) & 0xffff, R = word & 0xffff;
            const u16 L_ = L;
            const u16 R_ = R;
            const u16 idx = current_round - 1;

            u16 T = L xor (R & roundKey) xor idx;
            T = SBox(T);
            T = Permute(T);
            R = L_ xor (roundKey & T);
            L = R_ xor T;
            return static_cast<u32>(L) << 16 | R;
        }

        static u32 EncryptWord(const u32 word, const std::span<const u16> roundKey, const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");

            u32 res{word};
            for (int i = 0; i < round; ++i)
                res = Round(res, roundKey[i], i + 1);

            return res;
        }

        static u32 DecryptWord(const u32 word, const std::span<const u16> roundKey, const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");
            u32 res{word};
            for (int i = round - 1; i > -1; --i)
                res = InverseRound(res, roundKey[i], i + 1);

            return res;
        }

        static u32 PartialDecryptWord(const u32 word, const std::span<const u16> roundKey, const int round,
                                      const int to_round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small");
            u32 res{word};
            for (int i = round - 1; i >= to_round; --i)
                res = InverseRound(res, roundKey[i], i + 1);
            return res;
        }
};


template <int N>
class oracle
{
    public:
        explicit oracle(std::mt19937_64& rng) : key(utils::rand64(rng)) { BlockCipher::calRoundKey(key, roundKey, N); }
        explicit oracle(u64 key) : key(key) { BlockCipher::calRoundKey(key, roundKey, N); }
        [[nodiscard]] u32 getCipher(u32 word) const { return BlockCipher::EncryptWord(word, roundKey, N); }
        [[nodiscard]] u64 getKey() const { return key; }
        [[nodiscard]] const u16 * getRoundKey() const { return roundKey; }

    private:
        u64 key;
        u16 roundKey[N]{};
};
