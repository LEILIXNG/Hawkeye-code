void bad(const char *command) {
  // ruleid: CPP002
  ::system(
      command);
}

int system(int status) { return status; }

void good() {
  // ok: CPP002
  const char *example = "system(\"id\")";
  /* ok: CPP002
  system("rm -rf /");
  */
  // ok: CPP002
  runner.system("id");
  // ok: CPP002
  system(0);
}
