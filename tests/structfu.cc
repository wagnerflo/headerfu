#include "structfu.hh"
#include <cassert>
#include <string>

template <typename T>
void test_bitset() {
  T bs(32);

  for (int i = 0; i < 32; i++) {
    bs.flip_any_zero();
  }

  try {
    bs.flip_any_zero();
  }
  catch(std::out_of_range& exc) {
    assert(
      std::string(exc.what()) ==
      "no zero bits"
    );
  }
}

int main() {
  test_bitset<
    structfu::bitset
    >();
  test_bitset<
    structfu::detail::bitset<structfu::detail::CLZ>
    >();
  return 0;
}
