#include "sslfu.hh"
#include <cassert>
#include <string>

int main() {
  auto cl = sslfu::clientstream("www.google.de", "443");
  cl << "GET / HTTP/1.1\r\n"
     << "Host: www.google.de\r\n"
     << "\r\n"
     << std::flush;
  std::string line;
  std::getline(cl, line);
  assert(line == "HTTP/1.1 200 OK\r");
  return 0;
}
