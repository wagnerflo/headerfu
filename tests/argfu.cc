#include "argfu.hh"
#include <cassert>
#include <string>

#include <iostream>

int dispatch_abc() {
  return 1;
}

int dispatch_def() {
  return 2;
}

void test_dispatch() {
  const char* argv1[] = { "abc" };
  const char* argv2[] = { "def" };

  assert(
    argfu::dispatch (1, argv1, {
      { "abc", dispatch_abc },
      { "def", dispatch_def }
    })
    == 1
  );
  assert(
    argfu::dispatch (1, argv2, {
      { "abc", dispatch_abc },
      { "def", dispatch_def }
    })
    == 2
  );
}

void test_parser() {
  std::string opt_str;
  int opt_int;
  bool flag = false;

  argfu::parser parser =
    argfu::parser(progname)
      .option("str", 's', opt_str)
        .help("string option")
      .option("int", 'i', opt_int)
        .help("integer option")
      .flag("flag", 'f', flag)
        .help("flag");
  try {
    // parser.parse(args);
  }
  catch(const std::exception& ex) {
    std::cout << ex.what() << std::endl;
  }
}

int main() {
  test_dispatch();
  test_parser();
  return 0;
}
