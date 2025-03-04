static inline char *to_cstr(const char *src, size_t len) {
  char *ret = malloc(len + 1);
  memcpy(ret, src, len);
  ret[len] = '\0';
  return ret;
}

