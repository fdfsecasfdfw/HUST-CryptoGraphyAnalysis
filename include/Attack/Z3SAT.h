#pragma once

#include <vector>

#include "utils.h"
#include "z3++.h"

class Z3SAT
{
    public:
        static u64 crackCipher(
            int rounds,
            const std::vector<std::pair<u32, u32>>& VerifiPC,
            z3::context& ctx
        );
};
