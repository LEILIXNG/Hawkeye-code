void bad(char *path_template) {
  // ruleid: CPP008
  chmod("output.txt", 0777);
  // ruleid: CPP008
  mktemp(path_template);
}

void good() {
  // ok: CPP008
  chmod("output.txt", 0750);
  // ok: CPP008
  const char *text = "chmod(path, 0777)";
}
