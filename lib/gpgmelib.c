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

#include <locale.h>
#include <errno.h>
#include <string.h>

#include "gpgmelib.h"
#include "utils.h"


void
exit_with_err(gpgme_error_t err)
{
  fprintf(stderr, "Error occurred\n");
  fprintf(stderr, "%s\n", gpgme_strsource(err));
  exit(-1);

}

void
init_context(void)
{
  gpgme_error_t err;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_check_version(NULL);
  setlocale(LC_ALL, "");
  gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

  err = gpgme_engine_check_version(protocol);

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
    //fprintf(stdout, "  ->fpr : %s\n", key->fpr);
  }
}

void
print_key_info(gpgme_key_t key)
{
    fprintf(stdout, " KEY INFO\n");
    fprintf(stdout, "  ->email : %s\n", key->uids->email);
    fprintf(stdout, "  ->encrypt : %d\n", key->can_encrypt);
    //fprintf(stdout, "  ->fpr : %s\n", key->fpr);
}

int
select_key(gpgme_ctx_t ctx, char *fingerprint, gpgme_key_t *key)
{
  gpgme_error_t err;
  err = gpgme_get_key(ctx, fingerprint, key, 0);

  if(err) {
      fprintf(stderr, "Error selecting key\n");
      #ifdef DEBUG
      fprintf(stderr, "%s\n", err);
      #endif
      /* TODO: Not exit -1 but handle returning something to
       * the caller */
      return -1;
  }

  #ifdef DEBUG
  fprintf(stdout, "SELECTED KEY:\n");
  fprintf(stdout, "  ->email: %s\n", (*key)->uids->email);
  fprintf(stdout, "  ->encrypt: %d\n", (*key)->can_encrypt);
  fprintf(stdout, "  ->main fingerprint: %s\n", (*key)->fpr);
  #endif

  return 0;
}

char *
read_block(char *fin)
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

int
g_encrypt(char *fout, gpgme_ctx_t ctx, gpgme_key_t key[], \
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

  // Useful to see if the format is the expected one
  #ifdef DEBUG
  char *cipher_text = NULL;
  cipher_text = read_block(fout);
  fprintf(stdout, "%s\n", cipher_text);
  #endif

  return 0;
}

void
process_block(char *block)
{
    #ifdef DEBUG
    fprintf(stdout, "[NEW BLOCK RECEIVED]\n%s\n", block);
    fprintf(stdout, "[BLOCK LEN] %lu\n", strlen(block));
    #endif
    int bsize = strlen(block);
    char *line;
    size_t i = 0; /* Useful to scan a row of the block (line scan) */
    int cursor = 0; /* The global cursor to move on the block lines */

    while(bsize > 0) {
        //fprintf(stdout, "[EXECUTION] BSIZE: %d\n", bsize);
        do {
            //fprintf(stdout, "%c", block[(cursor+i)]);
            i++;
        }
        while(block[(cursor + i)] != '\n');

        line = (char*) malloc(i*sizeof(char) + 1);
        memcpy(line, (block + cursor), i * sizeof(char) + 1);
        line[i + 1] = '\0';

        if (line[0] != '#')
            process_provider(&provider_list, line);

        cursor += i;
        #ifdef DEBUG
        fprintf(stdout, "\nPROVIDER: %s\n", line);
        fprintf(stdout, "cursor: %d\n", cursor);
        fprintf(stdout, "i: %zu\n", i);
        #endif
        /* The +1 offset is necessary to include the newline char */
        bsize -= (i+1);
        //fprintf(stdout, "bsize: %d\n", bsize);
        i = 0;
        line = NULL;
        /* Avoid the newline char at the start of the next line 
         * So the idea is to start the cursor with +1 offset to
         * avoid the newline char coming from the previous line
         * */
        cursor++;
    }
    free(line);
}

void
print_gpgme_data(gpgme_data_t data)
{
    char *buf = (char*)malloc(BUFSIZE*sizeof(char));

    gpgme_data_seek (data, 0, SEEK_SET);
    while(gpgme_data_read(data, buf, BUFSIZE) > 0) {
        fprintf(stdout, "%s\n", buf);
    }
}

gpgme_data_t
decrypt(char *fout, gpgme_ctx_t ctx, \
        gpgme_data_t in, gpgme_data_t out)
{

  gpgme_error_t err;
  err = gpgme_data_new_from_file (&in, fout, 1);

  if (err)
      exit_with_err(err);

  gpgme_data_new (&out);
  gpgme_op_decrypt (ctx, in, out);

  #ifdef DEBUG
  print_gpgme_data(out);
  #endif

  return out;

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
