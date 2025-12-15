#include <chrono>

#include "BlockCipher.hh"
#include "Z3BlockCipher.h"
#include <iostream>

#include "mitm.h"
#include "Z3SAT.h"

std::mt19937_64 rng(std::random_device{}());

int main()
{
    constexpr int rounds = 6;
    constexpr int num_pairs = 5;
    std::vector<std::pair<u32, u32>> pc(num_pairs);
    const u64 key = utils::rand64(rng);
    u64 recoveredKey{};

    const oracle<rounds> oracle(key);
    for (int i = 0; i < num_pairs; i++)
    {
        const u32 pt = utils::rand32(rng);
        const u32 ct = oracle.getCipher(pt);
        pc[i].first = pt;
        pc[i].second = ct;
        std::cout << "plaintext: " << std::hex << pt << " ciphertext: " << ct << std::dec << std::endl;
    }

    const auto start = std::chrono::steady_clock::now();
    [&]<int R>()
    {
        if (R <= 2)
        {
            u16 roundKey[2];
            for (u32 k0 = 0; k0 < 1 << 16; k0 ++)
            {
                BlockCipher::calRoundKey(static_cast<u64>(k0), roundKey, R);
                bool flag = true;
                for (auto [plain, cipher]: pc)
                {
                    if (const u32 _cipher = BlockCipher::EncryptWord(plain, roundKey, R);_cipher != cipher)
                        flag = false;
                }
                if (flag)
                {
                    recoveredKey = k0;
                    break;
                }
            }
        }
        /* --------------------------------------------------------------------------------
         * Z3库代数攻击
        ----------------------------------------------------------------------------------- */
        else if constexpr (R > 2 && R < 5)
        {
            z3::context ctx;
            recoveredKey = Z3SAT::crackCipher(R, pc, ctx);
        }
        else if constexpr (R > 4 && R < 7)
        {
            recoveredKey = MITM<R>::crackCipher(pc, oracle);
        }
    }.operator()<rounds>();
    const auto end = std::chrono::steady_clock::now();
    std::cout << "true key: " << std::hex << key << std::dec << std::endl;
    const std::chrono::duration<double> diff = end - start;

    std::cout
    << rounds << "轮算法，破解前"
    << (rounds + 1) / 2 * 16 << "bit密钥为："
    << std::hex << recoveredKey << std::dec << std::endl;

    std::cout << "用时" << diff.count() << "s" << std::endl;

    return 0;
}
