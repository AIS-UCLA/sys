#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <fmt.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <dirent.h>
#include <netdb.h>
#include <bsd/unistd.h>

#ifdef __linux__
#include <linux/limits.h>
#elif __FreeBSD__
#include <limits.h>
#include <netinet/in.h>
#endif

#include <libssh2.h>
#include <libssh2_sftp.h>

#include "config.h"

#define REMOTE "cherf.ais-ucla.org"
#define REMOTE_PORT 22
#define REMOTE_USER "www"
#define MAX_SIZE 10 * 1024 * 1024
#define REMOTE_BASE "/www/www.ais-ucla.org/users"

#define PRIVKEY "-----BEGIN RSA PRIVATE KEY-----\n"\
  "...\n"\
  "-----END RSA PRIVATE KEY-----"


unsigned long dir_size(int fd, const char *path) {
  struct stat st;
  DIR *d;
  struct dirent *entry;
  char newpath[PATH_MAX];
  unsigned long ret = 0;

  d = opendir(path);
  if (!d) {
    fprint(fd, "opendir: %r\n");
    return 0;
  }
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    snprintf(newpath, PATH_MAX, "%s/%s", path, entry->d_name);
    if (lstat(newpath, &st) != 0) {
      fprint(fd, "lstat: %r\n");
      return 0;
    }
    if (S_ISDIR(st.st_mode))
      ret += dir_size(fd, newpath);
    else if (S_ISREG(st.st_mode)) {
      ret += (unsigned long)st.st_size;
    }
  }
  closedir(d);
  return ret;
}

int rm_dir(int fd, LIBSSH2_SFTP *sftp, const char *remote_path) {
  LIBSSH2_SFTP_HANDLE *dir;
  char buf[512];
  LIBSSH2_SFTP_ATTRIBUTES attrs;
  if ((dir = libssh2_sftp_opendir(sftp, remote_path)) == NULL) return 0;
  while (libssh2_sftp_readdir(dir, buf, 512, &attrs) > 0) {
    char remote_entry[PATH_MAX];

    if (strcmp(buf, ".") == 0 || strcmp(buf, "..") == 0) continue;
    snprintf(remote_entry, PATH_MAX, "%s/%s", remote_path, buf);

    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      // check if dir
      if ((attrs.permissions & 0170000) == 0040000 && rm_dir(fd, sftp, remote_entry) != 0) return -1;
      else if (libssh2_sftp_unlink(sftp, remote_entry) < 0) {
        fprint(fd, "failed to remote remote file: %s\n", remote_entry);
        return -1;
      }
    }
  }

  libssh2_sftp_closedir(dir);

  if (libssh2_sftp_rmdir(sftp, remote_path) < 0 && libssh2_sftp_last_error(sftp) != LIBSSH2_FX_NO_SUCH_FILE) {
    fprint(fd, "failed to remove remote directory: %s\n", remote_path);
    return -1;
  }
  return 0;
}


int upload_dir(int fd, LIBSSH2_SFTP *sftp, const char *local_path, const char *remote_path) {
  DIR *d;
  struct dirent *entry;
  char local_entry[PATH_MAX], remote_entry[PATH_MAX];

  if ((d = opendir(local_path)) == NULL) {
    fprint(fd, "opendir: %r\n");
    return -1;
  }
  if (libssh2_sftp_mkdir(sftp, remote_path, 0755)) {
    fprint(fd, "could not create remote directory: %s\n", remote_path);
    return -1;
  }
  while ((entry = readdir(d)) != NULL) {
    struct stat st;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    snprintf(local_entry, PATH_MAX, "%s/%s", local_path, entry->d_name);
    snprintf(remote_entry, PATH_MAX, "%s/%s", remote_path, entry->d_name);
    if (lstat(local_entry, &st) != 0) {
      fprint(fd, "lstat: %r\n");
      return -1;
    }
    if (S_ISDIR(st.st_mode) && upload_dir(fd, sftp, local_entry, remote_entry) != 0) return -1;
    else if (S_ISREG(st.st_mode)) {
      FILE *f;
      char buf[4096];
      size_t nread = 0;
      LIBSSH2_SFTP_HANDLE *handle;

      fprint(fd, "%s\n", local_entry);
      if ((f = fopen(local_entry, "r")) == NULL) {
        fprint(fd, "fopen: %r\n");
        return -1;
      }

      if ((handle = libssh2_sftp_open(sftp, remote_entry, LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644)) == NULL) {
        fprint(fd, "could not create remote file: %s\n", remote_entry);
        fclose(f);
        return -1;
      }

      while ((nread = fread(buf, 1, 4096, f)) > 0) {
        char *p = buf;
        while (nread > 0) {
          ssize_t nwrit;
          if ((nwrit = libssh2_sftp_write(handle, p, nread)) < 0) {
            fprint(fd, "could not write to remote file: %s\n", remote_entry);
            fclose(f);
            return -1;
          }
          p += nwrit;
          nread -= (size_t)nwrit;
        }
      }
      fclose(f);
      libssh2_sftp_close_handle(handle);
    } else fprint(fd, "refusing to copy non-regular, non-directory file: %s\n", local_path);
  }
  closedir(d);
  return 0;
}


void handle(int fd) {
  uid_t uid;
  gid_t gid;
  struct passwd *pw;
  char local_path[PATH_MAX], remote_path[PATH_MAX];
  struct stat st;
  unsigned long sz;
  struct hostent *he;
  int sock, rc;
  struct sockaddr_in sin;
  LIBSSH2_SESSION *session;
  LIBSSH2_SFTP *sftp;

  if (getpeereid(fd, &uid, &gid) == -1) {
    fprint(fd, "failed to get uid: %r\n");
    return;
  }

  if ((pw = getpwuid(uid)) == NULL) {
    fprint(fd, "could not find pw entry for uid %d: %r\n", uid);
    return;
  }

  if (snprintf(local_path, PATH_MAX, "%s/public_html", pw->pw_dir) >= PATH_MAX) {
    fprint(fd, "path too long\n");
    return;
  }

  if (stat(local_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    fprint(fd, "public_html directory does not exist\n");
    return;
  }

  if ((sz = dir_size(fd, local_path)) > MAX_SIZE) {
    fprint(fd, "public_html directory too big, max %d bytes\n", MAX_SIZE);
    return;
  }

  if (sz == 0) return;

  if (snprintf(remote_path, PATH_MAX, "%s/%s", REMOTE_BASE, pw->pw_name) >= PATH_MAX) {
    fprint(fd, "remote path too long\n");
    return;
  }

  if (libssh2_init(0) != 0) {
    fprint(fd, "libssh2 initialization failed\n");
    return;
  }

  if ((he = gethostbyname(REMOTE)) == NULL) {
    fprint(fd, "could not resolve host: %s\n", REMOTE);
    return;
  }

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprint(fd, "socket: %r\n");
    return;
  }

  sin = (struct sockaddr_in){ .sin_family = AF_INET, htons(REMOTE_PORT), .sin_addr = *(struct in_addr *)he->h_addr };

  if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    fprint(fd, "connect: %r\n");
    close(sock);
    return;
  }

  if ((session = libssh2_session_init()) == NULL) {
    fprint(fd, "could not initialize libssh2 session\n");
    close(sock);
    return;
  }

  libssh2_session_set_blocking(session, 1);
  if (libssh2_session_handshake(session, sock)) {
    fprint(fd, "libssh2 handshake failed\n");
    libssh2_session_free(session);
    close(sock);
    return;
  }

  if (libssh2_userauth_publickey_frommemory(session, REMOTE_USER, strlen(REMOTE_USER), NULL, 0, PRIVKEY, strlen(PRIVKEY), NULL) != 0) {
    fprint(fd, "embedded pubkey authentication failed\n");
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return;
  }

  if ((sftp = libssh2_sftp_init(session)) == NULL) {
    fprint(fd, "could not initialize libssh2 SFTP\n");
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return;
  }

  if (rm_dir(fd, sftp, remote_path) != 0) {
    fprint(fd, "could not delete remote directory\n");
    libssh2_sftp_shutdown(sftp);
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return;
  }

  if ((rc = upload_dir(fd, sftp, local_path, remote_path)) != 0)
    fprint(fd, "error uploading\n");
  else fprint(fd, "upload successful\n");

  libssh2_sftp_shutdown(sftp);
  libssh2_session_disconnect(session, "Normal Shutdown");
  libssh2_session_free(session);
  close(sock);
  libssh2_exit();

  return;
}

int main(void) {
  int s, fd;
  struct sockaddr_un sun;

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return -1;
  }

  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, DAEMON_SOCK);
  unlink(DAEMON_SOCK);

  if (bind(s, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
    perror("bind");
    return -1;
  }


  if (chmod(DAEMON_SOCK, 0777) == -1) {
    perror("chmod");
    return -1;
  }

  if (listen(s, 10) == -1) {
    perror("listen");
    return -1;
  }

  if (daemon(0, 0) == -1) {
    perror("daemon");
    return -1;
  }

  fd = open("/var/run/publish.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  fprint(fd, "%d\n", getpid());
  close(fd);

  while (1) {
    if ((fd = accept(s, NULL, NULL)) == -1) return -1;
    handle(fd);
    close(fd);
  }
}

