#include <string>

void bad() {
  // ruleid: CPP007
  std::string api_key = "live-secret-value";
  const char *password;
  // ruleid: CPP007
  password = "hunter2";
}

void good(const char *from_environment) {
  // ok: CPP007
  std::string username = "alice";
  // ok: CPP007
  const char *token = from_environment;
  // ok: CPP007
  const char *text = "password = secret";
}
