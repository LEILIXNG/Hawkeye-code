void bad(const char *program, char *const argv[]) {
  // ruleid: CPP003
  popen(program, "r");
  // ruleid: CPP003
  execvp(program,
         argv);
}

void good() {
  // ok: CPP003
  const char *text = "execve(path, argv, envp)";
  // ok: CPP003
  process.execv();
}
