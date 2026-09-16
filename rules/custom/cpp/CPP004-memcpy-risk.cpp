void bad(char *dst, const char *src, unsigned long length) {
  // ruleid: CPP004
  memcpy(dst,
         src,
         length);
}

void good() {
  // ok: CPP004
  const char *text = "memcpy(dst, src, length)";
  // ok: CPP004
  object.memcpy();
}
