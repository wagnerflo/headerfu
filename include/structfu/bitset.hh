/* Copyright 2022 Florian Wagner <florian@wagner-flo.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef STRUCTFU_BITSET_HH
#define STRUCTFU_BITSET_HH

#include <cstdint>
#include <memory>
#include <limits>
#include <stdexcept>

namespace structfu {

  namespace detail {
    constexpr uint32_t WORD(uint32_t bit) { return bit / 32; }
    constexpr uint32_t BIT(uint32_t bit)  { return bit % 32; }
    constexpr uint32_t UINT32(uint32_t n) { return static_cast<uint32_t>(n); }

    constexpr auto NONE_SET = UINT32(0);
    constexpr auto ALL_SET = UINT32(32);

    uint32_t CLZ(uint32_t word) {
      static const uint8_t de_bruijn[32] = {
        31, 22, 30, 21, 18, 10, 29,  2,
        20, 17, 15, 13,  9,  6, 28,  1,
        23, 19, 11,  3, 16, 14,  7, 24,
        12,  4,  8, 25,  5, 26, 27,  0
      };
      word |= word >> 1;
      word |= word >> 2;
      word |= word >> 4;
      word |= word >> 8;
      word |= word >> 16;
      return de_bruijn[UINT32(word * 0x07C4ACDDU) >> 27];
    }

    void change_bit(uint32_t& nbits, uint32_t& nzeros,
                    std::unique_ptr<uint32_t[]>& words,
                    uint32_t bit, int8_t val) {
      if (bit > nbits)
        throw std::out_of_range("invalid bit");

      auto nword = WORD(bit);
      auto word = words[nword];
      auto shift = UINT32(1) << BIT(bit);

      // bit is set
      if (word & shift) {
        if (val <= 0) {
          nzeros++;
          words[nword] = word ^ shift;
        }
      }
      // bit is not set
      else {
        if (val >= 0) {
          nzeros--;
          words[nword] = word ^ shift;
        }
      }
    }

    template <uint32_t (*CLZ)(uint32_t)>
    class bitset {
      friend void change_bit(uint32_t&, uint32_t&,
                             std::unique_ptr<uint32_t[]>,
                             uint32_t, int8_t);

      protected:
        uint32_t nbits;
        uint32_t nzeros;
        uint32_t nwords;
        uint32_t free_word = 0;
        std::unique_ptr<uint32_t[]> words;

      public:
        bitset(uint32_t n) {
          auto offset = BIT(n);
          auto plus1 = offset ? 1 : 0;

          nbits = nzeros = n;
          nwords = WORD(n) + plus1;
          words.reset(new uint32_t[nwords]());

          if (plus1)
            words[nwords - 1] = ~NONE_SET << offset;
        }

        void set(uint32_t bit) {
          change_bit(nbits, nzeros, words, bit,  1);
        }

        void clear(uint32_t bit) {
          change_bit(nbits, nzeros, words, bit, -1);
        }

        void flip(uint32_t bit) {
          change_bit(nbits, nzeros, words, bit,  0);
        }

        uint32_t flip_any_zero() {
          if (nzeros == 0)
            throw std::out_of_range("no zero bits");

          while (words[free_word] == UINT32_MAX) {
            if (++free_word == nwords)
              free_word = 0;
          }

          auto word = words[free_word];
          uint32_t offset = 0;

          if (word != 0) {
            offset = ALL_SET - CLZ(word);
            if (offset == 32)
              offset = ALL_SET - CLZ(~word) - 1;
          }

          nzeros--;
          words[free_word] = word | UINT32(1) << offset;

          return free_word * 32 + offset;
        }
    };
  }

#if __has_builtin(__builtin_clz)
  namespace detail {
    constexpr uint32_t CLZ_builtin(uint32_t word) {
      return detail::UINT32(__builtin_clz(word));
    }
  }
  using bitset = detail::bitset<detail::CLZ_builtin>;
#else
  using bitset = detail::bitset<detail::CLZ>;
#endif

  template <typename T>
  class bitmapped {
    protected:
      bitset map;
      T* items;

    public:
      bitmapped(uint32_t size)
        : map(size), items(new T[size]) {
        /* empty */
      }

      ~bitmapped() {
        delete[] items;
      }

      T& acquire() {
        return items[map.flip_any_zero()];
      }

      void release(T& item) {
        map.clear(static_cast<uint32_t>(&item - items));
      }
  };
}

#endif
