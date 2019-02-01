/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */



#include<locale.h>
#include<errno.h>

#include "gpgmelib.h"


void
exit_with_err(gpgme_error_t err)
{
  fprintf(stderr, "Error occurred\n");
  fprintf(stderr, "%s\n", gpgme_strsource(err));
  exit(-1);

}

void init_context(void)
{
  gpgme_error_t err;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_check_version(NULL);
  setlocale(LC_ALL, "");
  gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

  err = gpgme_engine_check_version(protocol);

  //We will see if it is wrapped properly ..
  if (err)
    exit_with_err(err);
}

void
print_keylist(gpgme_ctx_t ctx, gpgme_key_t key)
{
  gpgme_op_keylist_start(ctx, 0, 0);
  while ((gpgme_op_keylist_next(ctx, &key) != GPG_ERR_EOF) && key) {
    fprintf(stdout, " KEY INFO\n");
    fprintf(stdout, "  ->email : %s\n", key->uids->email);
    fprintf(stdout, "  ->encrypt : %d\n", key->can_encrypt);
    fprintf(stdout, "  ->fpr : %s\n", key->fpr);
  }
}

void
print_key_info(gpgme_key_t key)
{
    fprintf(stdout, " KEY INFO\n");
    fprintf(stdout, "  ->email : %s\n", key->uids->email);
    fprintf(stdout, "  ->encrypt : %d\n", key->can_encrypt);
    fprintf(stdout, "  ->fpr : %s\n", key->fpr);
}

void
select_key(gpgme_ctx_t ctx, char *fingerprint, gpgme_key_t *key)
{
  gpgme_get_key(ctx, fingerprint, key, 0);

  #ifdef DEBUG
  fprintf(stdout, "SELECTED KEY:\n");
  fprintf(stdout, "  ->email : %s\n", (*key)->uids->email);
  fprintf(stdout, "  ->encrypt : %d\n", (*key)->can_encrypt);
  #endif
}

void
write_file(char *fout, char *cipher_text, size_t bflen) {
  FILE *f;
  f = fopen(fout, "w");
  fwrite(cipher_text, sizeof(char), bflen, f);
  fclose(f);
}

char *
read_file(char *fin)
{
    FILE *f;

    if (fin == NULL)
        exit(ENOENT);

    f = fopen(fin, "r");
    if (f == NULL)
        exit(ENOENT);

    //Get the lenght of the file
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);

    //Rewind at the start of the file (rewind(f))
    fseek(f, 0, SEEK_SET);
    char *buf = (char*) malloc(fsize + 1);

    fread(buf, fsize, 1, f);

    fclose(f);

    return buf;
}

int encrypt(char *fout, gpgme_ctx_t ctx, gpgme_key_t key[], \
        gpgme_data_t in, gpgme_data_t out, gpgme_encrypt_flags_t flags)
{

  gpgme_error_t err;
  err = gpgme_op_encrypt(ctx, key, flags, in, out);

  if(err)
      exit_with_err(err);

  // NOW READING THE OUTPUT ..

  gpgme_data_seek(out, 0, SEEK_SET);

  size_t max_buflen = 2048, buflen;
  char *buf = malloc(max_buflen * sizeof(char));
  buflen = gpgme_data_read(out, buf, max_buflen);

  write_file(fout, buf, buflen);

  #ifdef DEBUG
  char *cipher_text = NULL;
  cipher_text = read_file(fout);
  fprintf(stdout, "%s\n", cipher_text);
  #endif

  return 0;
}


void
print_gpgme_data(gpgme_data_t data)
{
    char *buf = (char*)malloc(BUFSIZE*sizeof(char));

    gpgme_data_seek (data, 0, SEEK_SET);
    while(gpgme_data_read(data, buf, BUFSIZE) > 0) {
        fprintf(stdout, "TEXT:\n%s\n", buf);
    }
}

char*
decrypt(char *fout, gpgme_ctx_t ctx, \
        gpgme_data_t in, gpgme_data_t out)
{

  gpgme_error_t err;
  char *buf = (char*) malloc(sizeof(char));
  err = gpgme_data_new_from_file (&in, fout, 1);

  if (err)
      exit_with_err(err);

  gpgme_data_new (&out);
  gpgme_op_decrypt (ctx, in, out);

  //TODO: Processing out data to transform it into buf
  print_gpgme_data(out);

  return buf;

}

/**
 *
 * gcc -Wall -pedantic main.c -o main -lgpgme
 *
 * TEST CASE 1:
 * ./main -f 0458D4D1F41BD75C  -o ./encrypted_output_gpgme.gpg -i plaintext.txt
 *
 * TEST CASE 2:
 * ./main -f 0458D4D1F41BD75C  -o ./encrypted_output_gpgme.gpg -p ciao
 *
 */
