/* PB -- phonebook utility
 *
 * Copyright (c) 2024 Christopher Milan <chrismilan@ucla.edu>
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <pwd.h>
#include <ldap.h>

#define ATTRS (char *[]){"cn", "mobile", NULL}

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

  printf("querying %s\n", uname);

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
    if (ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY) { exit(1); }
    for (attr = ldap_first_attribute(ld, msg, &ber); attr != NULL; attr = ldap_next_attribute(ld, msg, ber)) {
      printf("%s: ", attr);
      if ((vals = ldap_get_values_len(ld, msg, attr)))
        for (i = 0; vals[i] != NULL; i++) printf("%s ", vals[i]->bv_val);
      printf("\n");
      ber_bvecfree(vals);
    }
  }
}

