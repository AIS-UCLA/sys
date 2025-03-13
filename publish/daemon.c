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
#include <archive.h>
#include <archive_entry.h>

#include "config.h"

#define REMOTE "cherf.ais-ucla.org"
#define REMOTE_PORT 22
#define REMOTE_USER "www"
#define MAX_SIZE 10 * 1024 * 1024
#define REMOTE_BASE "/www/www.ais-ucla.org/users"

#define PRIVKEY "-----BEGIN RSA PRIVATE KEY-----\n"\
  "...\n"\
  "-----END RSA PRIVATE KEY-----"

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
      if ((attrs.permissions & 0170000) == 0040000) {
        if (rm_dir(fd, sftp, remote_entry) != 0) return -1;
      } else if (libssh2_sftp_unlink(sftp, remote_entry) < 0) {
        fprint(fd, "failed to remove remote file: %s\n", remote_entry);
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

void canonicalize(char *path) {
  char *r = path, *w = path;
  while (*r) {
    if (*r == '/' && *(r+1) == '/') r++;
    if (*r == '/' && *(r+1) == '.' && *(r+2) == '/') r += 2;
    else *w++ = *r++;
  }
  *w = '\0';
}

int upload_dir(int fd, LIBSSH2_SFTP *sftp, struct archive *a, const char *remote_path) {
  int r;
  size_t sz = 0;
  struct archive_entry *entry;

  while ((r = archive_read_next_header(a, &entry)) != ARCHIVE_EOF) {
    char remote_entry[PATH_MAX];
    const char *local_entry;

    if (r == ARCHIVE_RETRY) continue;
    if (r != ARCHIVE_OK) {
      fprint(fd, "error reading archive: %A", a);
      return -1;
    }

    if ((sz + (size_t)archive_entry_size(entry)) > MAX_SIZE) {
      fprint(fd, "directory too big, (%d > %d bytes)\n", sz, MAX_SIZE);
      return -1;
    }

    local_entry = archive_entry_pathname(entry);

    // TODO: actually check traversal (ie. "./test..txt")
    if (strstr(local_entry, "..") != NULL) {
      fprint(fd, "path cannot contain \"..\", skipping %s\n", local_entry);
      continue;
    }

    snprintf(remote_entry, PATH_MAX, "%s/%s", remote_path, local_entry);

    if (archive_entry_filetype(entry) == AE_IFDIR) {
      // we need to canonicalize for mkdir
      canonicalize(remote_entry);

      if (libssh2_sftp_mkdir(sftp, remote_entry, 0755)) {
        fprint(fd, "could not create remote directory: %s\n", remote_entry);
        return -1;
      }
    } else if (archive_entry_filetype(entry) == AE_IFREG) {
      char buf[1048576], *p;
      size_t nread = 0;
      LIBSSH2_SFTP_HANDLE *handle;

      fprint(fd, "uploading %s\n", local_entry);

      if ((handle = libssh2_sftp_open(sftp, remote_entry, LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644)) == NULL) {
        fprint(fd, "could not create remote file: %s\n", remote_entry);
        return -1;
      }

      while ((nread = (size_t)archive_read_data(a, &buf, 1048576)) != 0) {
        if (nread == (size_t)ARCHIVE_WARN || nread == (size_t)ARCHIVE_FATAL) {
          fprint(fd, "error reading archive: %A\n", a);
          libssh2_sftp_close_handle(handle);
          return -1;
        }
        if (nread == (size_t)ARCHIVE_RETRY) continue;
        p = buf;
        while (nread > 0) {
          ssize_t nwrit;
          if ((nwrit = libssh2_sftp_write(handle, p, nread)) < 0) {
            fprint(fd, "could not write to remote file: %s\n", remote_entry);
            libssh2_sftp_close_handle(handle);
            return -1;
          }
          p += nwrit;
          nread -= (size_t)nwrit;
        }
      }
      libssh2_sftp_close_handle(handle);
    } else fprint(fd, "refusing to copy non-regular, non-directory file: %s\n", local_entry);
  }
  return 0;
}


void handle(int fd) {
  uid_t uid;
  gid_t gid;
  struct passwd *pw;
  struct archive *a;
  char local_path[PATH_MAX], remote_path[PATH_MAX];
  struct stat st;
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

  if ((a = archive_read_new()) == NULL) {
    fprint(fd, "failed to initialize libarchive\n");
    return;
  }
  archive_read_support_format_tar(a);
  if (archive_read_open_fd(a, fd, 1048576) != ARCHIVE_OK) {
    fprint(fd, "could not open tar archive: %A\n", a);
    archive_read_free(a);
    return;
  }

  if (snprintf(remote_path, PATH_MAX, "%s/%s", REMOTE_BASE, pw->pw_name) >= PATH_MAX) {
    fprint(fd, "remote path too long\n");
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

  fprint(fd, "deleting old files...\n");
  if (rm_dir(fd, sftp, remote_path) != 0) {
    fprint(fd, "could not delete remote directory\n");
    libssh2_sftp_shutdown(sftp);
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return;
  }

  if ((rc = upload_dir(fd, sftp, a, remote_path)) != 0)
    fprint(fd, "error uploading\n");
  else fprint(fd, "upload successful\n");

  archive_read_free(a);
  libssh2_sftp_shutdown(sftp);
  libssh2_session_disconnect(session, "Normal Shutdown");
  libssh2_session_free(session);
  close(sock);

  return;
}

int Afmt(Fmt *f) {
  struct archive *a;
  a = va_arg(f->args, struct archive *);
  return fmtprint(f, "%s", archive_error_string(a));
}

int main(void) {
  int s, fd;
  struct sockaddr_un sun;

  // setup unix socket
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

  // install libarchive error verb
  fmtinstall('A', Afmt);

  // initialize crypto for libssh2
  if (libssh2_init(0) != 0) {
    puts("libssh2 initialization failed");
    return -1;
  }

  // detatch, chdir /, and close 0 1 2
  if (daemon(0, 0) == -1) {
    perror("daemon");
    return -1;
  }

  // systemd likes to have PIDFile
  fd = open("/var/run/publish.pid", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  fprint(fd, "%d\n", getpid());
  close(fd);

  while (1) {
    // TODO: multithreading?
    if ((fd = accept(s, NULL, NULL)) == -1) return -1;
    handle(fd);
    close(fd);
  }
}

