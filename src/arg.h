/***
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
 *
 *  arg.h is useful to decouple the config parameters
 *  of the otp execution from the cmd line design
 */

#include <getopt.h>

static struct option long_options[] = {
    {"b32",      required_argument,  0,  'b' },
    {"file",     required_argument,  0,  'f' },
    {"gen",      required_argument,  0,  'g' },
    {"mode",     required_argument,  0,  'm' },
    {"version",  no_argument,        0,  'v' },
    {"fingerprint",   required_argument, 0,  'z' },
    {0,           0,                 0,  0   }
};

/**
 *  CMD LINE DESIGN:
 *  ----------------
 *  c_otp -f <file>
 *  c_otp -b <b32_sec>
 *  c_otp -m gpg -f <file>  -z fingerprint [-s]
 *  c_otp -g <plaintext_file> -z fingerprint
 *
 *  TEST
 *  ---
 *  ./c_otp -f providerrc.sample.gpg -m gpg -z 0458D4D1F41BD75C
 *  ./c_otp -f providerrc.sample.gpg -m gpg -z 0458D4D1F41BD75C -s
 *  ./c_otp -g providerrc.sample -z 0458D4D1F41BD75C
 *
 *  TEST CASE(s) [TODO]
 *  ---
 *  ./c_otp -f providerrc.sample -m gpg -z 0458D4D1F41BD75C (PLAIN TEXT FILE)
 *  ./c_otp -f providerrc.sample.gpg  (ENC PROVIDER LIST IN PLAINTEXT MODE)
 */
