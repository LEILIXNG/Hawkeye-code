struct Item { int value; void run(); };

void bad() {
  Item *item = nullptr;
  // ruleid: CPP006
  item->run();
}

void good(Item *replacement) {
  Item *item = nullptr;
  item = replacement;
  // ok: CPP006
  item->run();
  // ok: CPP006
  const char *text = "item->run()";
}

void aliases() {
  Item *item = NULL;
  Item *alias = item;
  // ruleid: CPP006
  *alias;
}

void guarded() {
  Item *item = nullptr;
  if (!item) {
    return;
  }
  // ok: CPP006
  item->run();
}
