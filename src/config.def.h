/***
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount@inventati.org>
 *
 *  Test Vector is composed by:
 *  key: ORSXG5A=
 *  msg: 1234
 *
 *  In order to test the hmac returned value from the openssl implementation
 *  check with bash launching:
 *
 *  $ echo -n "1234" | openssl dgst -sha1 -hmac "test"
 */

#ifndef CONFIG_H
#define CONFIG_H

#define T0 0
#define DIGITS 6
#define VALIDITY 30
#define TIME 2
#define VERSION 1.0

#endif

