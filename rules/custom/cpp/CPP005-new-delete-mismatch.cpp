void bad() {
  int *many = new int[8];
  // ruleid: CPP005
  delete many;

  int *one = new int(8);
  // ruleid: CPP005
  delete[] one;
}

void good() {
  int *many = new int[8];
  // ok: CPP005
  delete[] many;
  int *one = new int(8);
  // ok: CPP005
  delete one;
}
