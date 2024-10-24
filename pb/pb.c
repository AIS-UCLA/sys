/* PB -- phonebook utility
 *
 * Copyright (c) 2024 Christopher Milan <chrismilan@ucla.edu>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <pwd.h>
#include <ldap.h>

#include "hc.h"

#define ATTRS (char *[]){"description", "o", "uid", "cn", "mobile", NULL}

__attribute__((noreturn))
void usage(void) {
  fprintf(stderr, "usage: pb [user]\n");
  exit(1);
}

int main(int argc, char **argv) {
  char *uname, *dn, *pw;
  LDAP *ld;
  LDAPMessage *res, *msg;
  int i, err;
  struct hc_data f  = { .next = NULL };
  struct hc_data e1 = { .next = &f };
  struct hc_data m1 = { .next = &e1 };
  struct hc_data m0 = { .next = &m1 };
  struct hc_data e0 = { .next = &m0 };
  struct hc_data h  = { .next = &e0 };

  if (argc == 1) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
      fprintf(stderr, "no passwd entry for self\n");
      exit(1);
    }
    uname = pw->pw_name;
  } else if (argc == 2) uname = argv[1];
  else usage();
  if (strlen(uname) > 32) {
    fprintf(stderr, "username too long\n");
    exit(1);
  }

  if ((err = ldap_initialize(&ld, "ldap://ldap.ais-ucla.org"))) {
    fprintf(stderr, "could not initalize LDAP (code %d)", err);
    exit(1);
  }

  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &(int){3})) {
    fprintf(stderr, "could not set ldap version");
    exit(1);
  }

  if (ldap_start_tls_s(ld, NULL, NULL)) {
    fprintf(stderr, "STARTTLS failed, refusing to authenticate in cleartext\n");
    exit(1);
  }

  dn = (char *)malloc(64);
  snprintf(dn, 64, "uid=%s,ou=Users,dc=ais-ucla,dc=org", uname);

  if ((err = ldap_search_ext_s(ld, dn, LDAP_SCOPE_BASE, NULL, ATTRS, 0, NULL, NULL, NULL, -1, &res))) {
    fprintf(stderr, "failed to search LDAP: %s\n", ldap_err2string(err));
    exit(1);
  }

  for (msg = ldap_first_message(ld, res); msg != NULL; msg = ldap_next_message(ld, msg)) {
    char *attr;
    BerVarray *vals;
    BerElement *ber;
    if (ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY) continue;
    for (attr = ldap_first_attribute(ld, msg, &ber); attr != NULL; attr = ldap_next_attribute(ld, msg, ber)) {
      if ((vals = ldap_get_values_len(ld, msg, attr))) {
        if (strcmp(attr, "description") == 0) m1.center = vals[0]->bv_val;
        else if (strcmp(attr, "o") == 0) h.right = vals[0]->bv_val;
        else if (strcmp(attr, "uid") == 0) f.left = vals[0]->bv_val;
        else if (strcmp(attr, "cn") == 0) m0.center = vals[0]->bv_val;
        else if (strcmp(attr, "mobile") == 0) h.left = vals[0]->bv_val;
      }
    }
  }

  printf("\n");
  render(&h, 0);
  printf("\n");
}

