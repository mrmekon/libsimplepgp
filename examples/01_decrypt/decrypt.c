#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include <simplepgp.h>

#define SECKEY_BUF 2048
#define CTEXT_BUF 1024

#define KEY_PASS "test"

int main(int argc, char **argv) {
  char seckey[SECKEY_BUF];
  char ctext[CTEXT_BUF];
  int fd;
  int seckey_len, ctext_len;
  spgp_packet_t *pkt;

  printf("simplepgp decrypt example.\n");

  fd = open("test1_sec.pgp", O_RDONLY);
  if (fd < 0) { perror("seckey open"); return 1; }
  if ((seckey_len = read(fd, seckey, SECKEY_BUF)) < 0) {
    perror("seckey read"); return 1;
  }
  close(fd);

  fd = open("ciphertext.pgp", O_RDONLY);
  if (fd < 0) { perror("cipher open"); return 1; }
  if ((ctext_len = read(fd, ctext, CTEXT_BUF)) < 0) {
    perror("cipher read"); return 1;
  }
  close(fd);

  if (spgp_init() != 0) {
    fprintf(stderr, "error: %s\n", spgp_err_str(spgp_err()));
    return 1;
  }

  spgp_debug_log_set(1);

  pkt = spgp_decode_message(seckey, seckey_len);
  if (NULL == pkt) {
    fprintf(stderr, "error: %s\n", spgp_err_str(spgp_err()));
    return 1;
  }

  if (spgp_decrypt_all_secret_keys(pkt, KEY_PASS, strlen(KEY_PASS)) != 0) {
    fprintf(stderr, "error: %s\n", spgp_err_str(spgp_err()));
    return 1;
  }

  pkt = spgp_decode_message(ctext, ctext_len);
  if (NULL == pkt) {
    fprintf(stderr, "error: %s\n", spgp_err_str(spgp_err()));
    return 1;
  }

  spgp_close();

  return 0;
}
