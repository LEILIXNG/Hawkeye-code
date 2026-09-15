#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/stat.h>

struct Record {
  void process();
};

void unsafe_copy(char *destination, const char *input) {
  strcpy(destination, input);
}

void shell_command(const char *input) {
  system(input);
}

void execute_program(const char *path, char *const arguments[]) {
  execvp(path, arguments);
}

void unchecked_copy(char *destination, const char *input, unsigned long length) {
  memcpy(destination, input, length);
}

void mismatched_allocation() {
  int *values = new int[16];
  delete values;
}

void obvious_null_dereference() {
  Record *record = nullptr;
  record->process();
}

void embedded_credential() {
  std::string api_key = "demo-hard-coded-key";
}

void permissive_output() {
  chmod("output.txt", 0777);
}
