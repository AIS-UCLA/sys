/* SUJAIL -- A script to allow unprivileged users to jexec jails
 *
 * Copyright (c) 2024 Christopher Milan <chrismilan@ucla.edu>
 *
 * Inspired by OpenBSD doas(1).
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <login_cap.h>

#define INIT_RT_SZ  16
#define NGROUPS_MAX 16
#define GID_MAX     65535
#define UID_MAX     65535

struct rule {
  char *ident;
  char *jail;
  bool permit;
};



int parseuid(const char *s, uid_t *uid) {
  struct passwd *pw;
  const char *errstr;

  if ((pw = getpwnam(s)) != NULL) {
    *uid = pw->pw_uid;
    if (*uid == UID_MAX) return -1;
    return 0;
  }
  *uid = strtonum(s, 0, UID_MAX - 1, &errstr);
  if (errstr) return -1;
  return 0;
}

int parsegid(const char *s, gid_t *gid) {
  struct group *gr;
  const char *errstr;

  if ((gr = getgrnam(s)) != NULL) {
    *gid = gr->gr_gid;
    if (*gid == GID_MAX) return -1;
    return 0;
  }
  *gid = strtonum(s, 0, GID_MAX - 1, &errstr);
  if (errstr) return -1;
  return 0;
}

int uidcheck(const char *s, uid_t desired) {
  uid_t uid;

  if (parseuid(s, &uid) != 0) return -1;
  if (uid != desired) return -1;
  return 0;
}

int match(uid_t uid, gid_t *groups, int ngroups, const char *jail,
          const struct rule r) {
  int i;
  if (r.ident[0] == ':') {
    gid_t rgid;
    if (parsegid(r.ident + 1, &rgid) == -1) return 0;
    for (i = 0; i < ngroups; i++)
      if (rgid == groups[i]) break;
    if (i == ngroups) return 0;
  } else if (uidcheck(r.ident, uid) != 0) return 0;
  if (strcmp(r.jail, "*") != 0)
    if (strcmp(r.jail, jail)) return 0;
  return 1;
}

int permit(uid_t uid, gid_t *groups, int ngroups, const char *jail,
           const struct rule *rules, int nrules) {
  int i;
  const struct rule *lastr = NULL;

  for (i = 0; i < nrules; i++)
    if (match(uid, groups, ngroups, jail, rules[i]))
      lastr = &rules[i];

  if (!lastr) return 0;
  if (lastr->permit) return 1;
  return 1;
}

int parseconfig(const char *filename, struct rule **rt) {
  FILE *fd;
  struct stat sb;
  char line[1024];
  int r_idx = 0;
  int rt_sz = INIT_RT_SZ;
  int lineno;

  fd = fopen(filename, "r");
  if (!fd) {
    fprintf(stderr, "could not open config file %s\n", filename);
    exit(1);
  }

  // verify config permissions
  if (fstat(fileno(fd), &sb)) {
    fprintf(stderr, "fstat(\"%s\")\n", filename);
    exit(1);
  }
  if ((sb.st_mode & (S_IWGRP|S_IWOTH))) {
    fprintf(stderr, "%s is writable by group or other\n", filename);
    exit(1);
  }
  if (sb.st_uid) {
    fprintf(stderr, "%s is not owned by root\n", filename);
    exit(1);
  }

  *rt = (struct rule *) malloc(sizeof(struct rule) * rt_sz);
  for (lineno = 0; fgets(line, 1024, fd); lineno++) {
    struct rule rule;
    char *action;
    char *l = line;
    if (line[strlen(line)-1] == '\n') line[strlen(line)-1] = '\0';

    if (line[0] == '#') continue;

    if (r_idx >= rt_sz) {
      if (r_idx > 512) {
        fprintf(stderr, "%s has too many rules\n", filename);
        exit(1);
      }
      free(rt);
      rt_sz *= 2;
      *rt = (struct rule *) malloc(sizeof(struct rule) * rt_sz);
    }

    action = strsep(&l, " ");
    if (strcmp(action, "permit")) rule.permit = true;
    else if (strcmp(action, "deny")) rule.permit = false;
    else {
      fprintf(stderr, "%s:%d error parsing action, must be \"permit\" or \"deny\"\n", filename, lineno);
      exit(1);
    }

    rule.ident = strsep(&l, " ");
    rule.jail = strsep(&l, " ");

    if ((rule.ident == NULL) || (rule.jail == NULL)) {
      fprintf(stderr, "%s:%d error parsing\n", filename, lineno);
      exit(1);
    }

    (*rt)[r_idx++] = rule;
  }

  fclose(fd);

  return r_idx;
}

void usage(void) {
  fprintf(stderr, "usage: sujail jail\n");
  exit(1);
}

int main(int argc, char **argv) {
  struct passwd *pw, *rootpw;
  uid_t uid;
  int nrules, ngroups;
  struct rule *rt;
  gid_t groups[NGROUPS_MAX + 1];

  if (argc != 2) usage();

  nrules = parseconfig("/etc/sujail.conf", &rt);


  uid = getuid();
  pw = getpwuid(uid);
  if (pw == NULL) {
    fprintf(stderr, "no passwd entry for self\n");
    exit(1);
  }
  rootpw = getpwuid(0);
  if (pw == NULL) {
    fprintf(stderr, "failed to get pw entry for root\n");
    exit(1);
  }

  ngroups = getgroups(NGROUPS_MAX, groups);
  if (ngroups == -1) {
    fprintf(stderr, "cant get groups\n");
    exit(1);
  }
  groups[ngroups++] = getgid();


  if (permit(uid, groups, ngroups, argv[1], rt, nrules)) {
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "jail exec not permitted for %s: %s", pw->pw_name, argv[1]);
    fprintf(stderr, "%s is not permitted to run jail %s, this incident has been reported\n", pw->pw_name, argv[1]);
    exit(1);
  } else {
    setusercontext(NULL, rootpw, 0, LOGIN_SETUSER);
    free(rt);
    execl("/usr/sbin/jexec", "-l", argv[1], "login", "-f",  "root", (char *)NULL);
  }
}

