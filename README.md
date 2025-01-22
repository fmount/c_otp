YET ANOTHER SIMPLE TOTP TOKEN GENERATOR IN PURE C
=======


This is a simple (re)implementation of the **TOTP Token generator** written in Pure C and following the 
references:

* [RFC6238](https://tools.ietf.org/html/rfc6238)
* [RFC4226](https://tools.ietf.org/html/rfc4226)

It doesn't expose any external api, you can just build it and use with the most popular provider
that implement the RFC specification.

BUILD FROM SRC
----
You can simply build it using the provided `Makefile`.
When you run **make** it generates a `./usr/bin/c_otp` within the project root
dir with the result of the compilation.
Before building, make sure the dependencies are installed.

For example:

```bash
$ podman run --rm --name c_otp -it quay.io/fedora/fedora:latest /bin/bash
$ dnf install -y make git gcc openssl-devel
$ git clone https://github.com/fmount/c_otp
$ pushd c_otp
$ make
```

Run the example:
```bash
$ ./usr/bin/c_otp -f providerrc
[(google: 418346)(amazon: 071288)(protonmail: 418346)]
```

USAGE
---

```
$ ./c_otp -h
Usage ./bin/c_otp [-f fname] | [-b b32_secretkey] [-m mode] [-v]
```

There are two available modes:

* **direct**: it is used to run a totp calculation *on the fly*.

```bash
$ c_otp -b <BASE32_SECRET>
```

If the secret is a valid `base32`, it is first decoded and the computation is
performed.
To build a simple test vector, you can generate a key example with the
following:

```bash
$ echo "test" | base32 (ORSXG5A=)
```

* **provider**: it is possible to define a provider list in a *providerrc* file
that can be passed as input:

```bash
$ ./usr/bin/c_otp -f providerrc -s
```

The `-s` flag is used to print on *stdout* the array containing all the defined
providers.
As the helper suggests, it is also possible to pass `-m <mode>` option that can
be used to provide a json like format output, useful to interact with other
kind of applications, or filter the output using tools like `jq`.

For example, running the program with `-m 1` produces a json output:

```bash
$ ./usr/bin/c_otp -f providerrc -m 1
```

```
{
    "providers": {
        "protonmail": "123456",
        "google": "123456",
        "amazon": "123456",
    }
}
```

```bash
$ ./c_otp -f providerrc -m 1 | jq '.providers.protonmail'
```
