void bad(char *dst, const char *src) {
  // ruleid: CPP001
  strcpy(dst, src);
  // ruleid: CPP001
  std::strcat(dst, src);
  // ruleid: CPP001
  sprintf(dst,
          "%s", src);
  // ruleid: CPP001
  gets(dst);
}

void good() {
  // ok: CPP001
  // strcpy(dst, src);
  // ok: CPP001
  const char *text = "strcpy(dst, src)";
  // ok: CPP001
  int strcpy = 1;
  // ok: CPP001
  object.strcpy();
}
