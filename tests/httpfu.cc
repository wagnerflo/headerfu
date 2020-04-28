#include "sslfu.hh"
#include "httpfu.hh"
#include <cassert>
#include <string>

#include <iostream>

int main() {
  auto cl = sslfu::clientstream("example.com", "443");
  auto resp =
    httpfu::request::get("/")
      .header("Host", "example.com")
      .send(cl);

  assert(resp.status_code() == 200);
  assert(resp.reason() == "OK");

  for (const auto& p : resp.headers()) {
    std::cerr << p.first << " => [" << p.second << "]" << std::endl;
  }

  std::cerr << "[" << resp.body() << "]" << std::endl;

  return 0;
}
