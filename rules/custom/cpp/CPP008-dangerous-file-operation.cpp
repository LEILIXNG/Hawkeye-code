void bad(char *path_template) {
  // ruleid: CPP008
  chmod("output.txt", 0777);
  // ruleid: CPP008
  mktemp(path_template);
  // ruleid: CPP008
  chmod("shared.txt", 0666);
  // ruleid: CPP008
  fopen("/tmp/predictable.log", "w");
  // ruleid: CPP008
  open("/tmp/shared.log", O_CREAT | O_WRONLY, 0666);
}

void good() {
  // ok: CPP008
  chmod("output.txt", 0750);
  // ok: CPP008
  fopen("/var/lib/app/report.txt", "r");
  // ok: CPP008
  const char *text = "chmod(path, 0777)";
}
