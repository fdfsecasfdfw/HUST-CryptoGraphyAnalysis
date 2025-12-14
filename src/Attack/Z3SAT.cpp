#include "Z3SAT.h"

#include "Z3BlockCipher.h"

u64 Z3SAT::crackCipher(
    const int rounds,
    const std::vector<std::pair<u32, u32>>& VerifiPC,
    z3::context& ctx)
{
    if (rounds > 4)
        return 0;

    std::vector<z3::expr> roundKey;
    roundKey.reserve(rounds);
    for (int i = 0; i < rounds; i++)
        roundKey.emplace_back(ctx.bv_val(0, 16));
    const auto key = ctx.bv_const("key", 64);
    Z3BlockCipher::calRoundKey(ctx, key, roundKey, rounds);
    z3::solver s(ctx);

    s.add(key.extract(63, 32) == ctx.bv_val(0, 32));

    for (auto [plain, cipher] : VerifiPC)
    {
        z3::expr plainExpr = ctx.bv_val(plain, 32);
        z3::expr cipherExpr = ctx.bv_val(cipher, 32);
        z3::expr gct = Z3BlockCipher::EncryptWord(ctx, plainExpr, roundKey, rounds);
        s.add(gct == cipherExpr);
    }

    if (s.check() == z3::sat)
    {
        const auto m = s.get_model();
        const auto recoveredKey = m.eval(key).get_numeral_uint64();
        return recoveredKey;
    }
    return 0;
}
