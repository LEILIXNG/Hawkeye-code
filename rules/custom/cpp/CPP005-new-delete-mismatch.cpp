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

int *make_many() {
  return new int[4];
}

void destroy_wrong(int *value) {
  // ruleid: CPP005
  delete value;
}

void transferred() {
  int *items = make_many();
  destroy_wrong(items);
}

struct Holder {
  int *items;
  Holder() { items = new int[4]; }
  ~Holder() {
    // ruleid: CPP005
    delete items;
  }
};
