#pragma once

#include "z3++.h"
#include <span>

#include "utils.h"


class Z3BlockCipher
{
    public:
        static z3::expr SBox(const z3::expr& x) { return (z3::shl(x, 2) & z3::shl(x, 1)) ^ x; }

        static z3::expr Permute(const z3::expr& x) { return x.rotate_left(3) ^ x.rotate_left(9) ^ x.rotate_right(2); }

        static void calRoundKey(z3::context& ctx, const z3::expr& key, std::span<z3::expr> roundKey, const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");

            z3::expr k[4] = {
                key.extract(15, 0), key.extract(31, 16),
                key.extract(47, 32), key.extract(63, 48)
            };

            for (int i = 0; i < round; i++)
            {
                z3::expr kt = ctx.bv_val(0, 16);
                if (i < 8)
                    kt = k[i / 2];
                else
                    kt = roundKey[2 * (i / 2) - 7] ^ ctx.bv_val(i / 2 - 4, 16);
                roundKey[i] = (i % 2) ? ~kt : kt;
            }
        }

        static z3::expr Round(z3::context& ctx, const z3::expr& word, const z3::expr& roundKey, const int current_round)
        {
            z3::expr L = word.extract(31, 16);
            z3::expr R = word.extract(15, 0);
            const z3::expr L_old = L;
            const z3::expr R_old = R;

            const int idx_ = current_round - 1;
            const z3::expr idx = ctx.bv_val(idx_, 16);

            z3::expr T = (roundKey & L) ^ R ^ idx;

            T = SBox(T);
            T = Permute(T);

            L = R_old ^ (roundKey & T);
            R = L_old ^ T;

            return z3::concat(L, R);
        }

        static z3::expr InverseRound(z3::context& ctx, const z3::expr& word, const z3::expr& roundKey,
                                     const int current_round)
        {
            z3::expr L = word.extract(31, 16);
            z3::expr R = word.extract(15, 0);
            const z3::expr L_old = L;
            const z3::expr R_old = R;

            const u16 idx = current_round - 1;
            z3::expr T = L ^ (R & roundKey) ^ ctx.bv_val(idx, 16);
            T = SBox(T);
            T = Permute(T);
            R = L_old ^ (roundKey & T);
            L = R_old ^ T;
            return z3::concat(L, R);
        }

        static z3::expr EncryptWord(z3::context& ctx, const z3::expr& word, const std::span<const z3::expr> roundKey,
                                    const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");

            z3::expr res = word;

            for (int i = 0; i < round; i++)
                res = Round(ctx, res, roundKey[i], i + 1);

            return res;
        }

        static z3::expr DecryptWord(z3::context& ctx, const z3::expr& word, const std::span<const z3::expr> roundKey,
                                    const int round)
        {
            if (roundKey.size() < round)
                throw std::runtime_error("roundKey Array too small, index out of bound");

            z3::expr res = word;
            for (int i = round - 1; i > -1; --i)
                res = InverseRound(ctx, res, roundKey[i], i + 1);

            return res;
        }
};
