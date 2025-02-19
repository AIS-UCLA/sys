#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <pwd.h>
#include <dirent.h>
#include <netdb.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#include "config.h"

unsigned long dir_size(const char *path) {
  struct stat st;
  DIR *d;
  struct dirent *entry;
  char newpath[PATH_MAX];
  unsigned long ret = 0;

  d = opendir(path);
  if (!d) {
    perror("opendir");
    exit(-1);
  }
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    snprintf(newpath, PATH_MAX, "%s/%s", path, entry->d_name);
    if (lstat(newpath, &st) != 0) {
      perror("lstat");
      exit(-1);
    }
    if (S_ISDIR(st.st_mode))
      ret += dir_size(newpath);
    else if (S_ISREG(st.st_mode)) {
      ret += (unsigned long)st.st_size;
    }
  }
  closedir(d);
  return ret;
}

int rm_dir(LIBSSH2_SFTP *sftp, const char *remote_path) {
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
      if ((attrs.permissions & 0170000) == 0040000 && rm_dir(sftp, remote_entry) != 0) return -1;
      else if (libssh2_sftp_unlink(sftp, remote_entry) < 0) {
        fprintf(stderr, "failed to remote remote file: %s\n", remote_entry);
        return -1;
      }
    }
  }

  libssh2_sftp_closedir(dir);

  if (libssh2_sftp_rmdir(sftp, remote_path) < 0 && libssh2_sftp_last_error(sftp) != LIBSSH2_FX_NO_SUCH_FILE) {
    fprintf(stderr, "failed to remove remote directory: %s\n", remote_path);
    return -1;
  }
  return 0;
}


int upload_dir(LIBSSH2_SFTP *sftp, const char *local_path, const char *remote_path) {
  DIR *d;
  struct dirent *entry;
  char local_entry[PATH_MAX], remote_entry[PATH_MAX];

  if ((d = opendir(local_path)) == NULL) {
    perror("opendir");
    return -1;
  }
  if (libssh2_sftp_mkdir(sftp, remote_path, 0755)) {
    fprintf(stderr, "could not create remote directory: %s\n", remote_path);
    return -1;
  }
  while ((entry = readdir(d)) != NULL) {
    struct stat st;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    snprintf(local_entry, PATH_MAX, "%s/%s", local_path, entry->d_name);
    snprintf(remote_entry, PATH_MAX, "%s/%s", remote_path, entry->d_name);
    if (lstat(local_entry, &st) != 0) {
      perror("lstat");
      return -1;
    }
    if (S_ISDIR(st.st_mode) && upload_dir(sftp, local_entry, remote_entry) != 0) return -1;
    else if (S_ISREG(st.st_mode)) {
      FILE *f;
      char buf[4096];
      size_t nread = 0;
      LIBSSH2_SFTP_HANDLE *handle;

      puts(local_entry);
      if ((f = fopen(local_entry, "r")) == NULL) {
        perror("fopen");
        return -1;
      }

      if ((handle = libssh2_sftp_open(sftp, remote_entry, LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644)) == NULL) {
        fprintf(stderr, "could not create remote file: %s\n", remote_entry);
        fclose(f);
        return -1;
      }

      while ((nread = fread(buf, 1, 4096, f)) > 0) {
        char *p = buf;
        while (nread > 0) {
          ssize_t nwrit;
          if ((nwrit = libssh2_sftp_write(handle, p, nread)) < 0) {
            fprintf(stderr, "could not write to remote file: %s\n", remote_entry);
            fclose(f);
            return -1;
          }
          p += nwrit;
          nread -= (size_t)nwrit;
        }
      }
      fclose(f);
      libssh2_sftp_close_handle(handle);
    } else fprintf(stderr, "refusing to copy non-regular, non-directory file: %s\n", local_path);
  }
  closedir(d);
  return 0;
}


int main(void) {
  uid_t uid;
  struct passwd *pw;
  char local_path[PATH_MAX], remote_path[PATH_MAX];
  struct stat st;
  struct hostent *he;
  int sock, rc;
  struct sockaddr_in sin;
  LIBSSH2_SESSION *session;
  LIBSSH2_SFTP *sftp;

  uid = getuid();
  if ((pw = getpwuid(uid)) == NULL) {
    fprintf(stderr, "could not find pw entry for uid %d\n", uid);
    return -1;
  }

  if (snprintf(local_path, PATH_MAX, "%s/public_html", pw->pw_dir) >= PATH_MAX) {
    fprintf(stderr, "path too long\n");
    return -1;
  }

  if (stat(local_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    fprintf(stderr, "public_html directory does not exist\n");
    return -1;
  }

  if (dir_size(local_path) > MAX_SIZE) {
    fprintf(stderr, "public_html directory too big, max %d bytes\n", MAX_SIZE);
    return -1;
  }

  if (snprintf(remote_path, PATH_MAX, "%s/%s", REMOTE_BASE, pw->pw_name) >= PATH_MAX) {
    fprintf(stderr, "remote path too long\n");
    return -1;
  }

  if (libssh2_init(0) != 0) {
    fprintf(stderr, "libssh2 initialization failed\n");
    return -1;
  }

  if ((he = gethostbyname(REMOTE)) == NULL) {
    fprintf(stderr, "could not resolve host: %s\n", REMOTE);
    return -1;
  }

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return -1;
  }

  sin = (struct sockaddr_in){ .sin_family = AF_INET, htons(REMOTE_PORT), .sin_addr = *(struct in_addr *)he->h_addr };

  if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    perror("connect");
    close(sock);
    return -1;
  }

  if ((session = libssh2_session_init()) == NULL) {
    fprintf(stderr, "could not initialize libssh2 session\n");
    close(sock);
    return -1;
  }

  libssh2_session_set_blocking(session, 1);
  if (libssh2_session_handshake(session, sock)) {
    fprintf(stderr, "libssh2 handshake failed\n");
    libssh2_session_free(session);
    close(sock);
    return -1;
  }

  if (libssh2_userauth_publickey_frommemory(session, REMOTE_USER, strlen(REMOTE_USER), NULL, 0, PRIVKEY, strlen(PRIVKEY), NULL) != 0) {
    fprintf(stderr, "embedded pubkey authentication failed\n");
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return -1;
  }

  if ((sftp = libssh2_sftp_init(session)) == NULL) {
    fprintf(stderr, "could not initialize libssh2 SFTP\n");
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return -1;
  }

  if (rm_dir(sftp, remote_path) != 0) {
    fprintf(stderr, "could not delete remote directory\n");
    libssh2_sftp_shutdown(sftp);
    libssh2_session_disconnect(session, "Normal Shutdown");
    libssh2_session_free(session);
    close(sock);
    return -1;
  }

  if ((rc = upload_dir(sftp, local_path, remote_path)) != 0)
    fprintf(stderr, "error uploading\n");
  else puts("upload successful");

  libssh2_sftp_shutdown(sftp);
  libssh2_session_disconnect(session, "Normal Shutdown");
  libssh2_session_free(session);
  close(sock);
  libssh2_exit();

  return rc;
}

