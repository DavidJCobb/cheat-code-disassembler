#pragma once
#include <cstdint>

struct action_replay_code {
   public:
      static constexpr const std::uint32_t SEEDS[4] = {
         0x7AA9648F,
         0x7FAE6994,
         0xC0EFAAD5,
         0x42712C57
      };
      static constexpr const std::uint32_t MAGIC = 0x9E3779B9;

   public:
      std::uint32_t opcode  = 0;
      std::uint32_t operand = 0;

      constexpr void decrypt() {
         for (size_t i = 32; i > 0; --i) {
            operand -= (opcode  * 16 + SEEDS[2]) ^ (opcode  + MAGIC * i) ^ ((opcode  >> 5) + SEEDS[3]);
            opcode  -= (operand * 16 + SEEDS[0]) ^ (operand + MAGIC * i) ^ ((operand >> 5) + SEEDS[1]);
         }
      }
};
