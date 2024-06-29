# SRP - Secure Remote Password
This is a Secure Remote Password (SRP) implementation in OCaml. 

SRP is a password-authenticated key exchange (PAKE) protocol. It allows a user to authenticate themselves to a server without ever sending their password over the network. It is resistant to dictionary attacks, eavesdropping, and replay attacks.

Some references below:
- [LinusU/secure-remote-password](https://github.com/LinusU/secure-remote-password)
- [mozilla/node-srp](https://github.com/mozilla/node-srp)
- [SRP Protocol Design](http://srp.stanford.edu/design.html)
- [RFC 2945](https://tools.ietf.org/html/rfc2945)
- [RFC 5054](https://tools.ietf.org/html/rfc5054)

This project mainly use:
- [Zarith](https://github.com/ocaml/Zarith) library to handle the big integer calculation.
- `Mirage-crypto` library to handle the hash function.

## Environment Setup
`opam install --deps-only -t .`

Use the above command to install all the dependencies.(See the `srp.opam` file for the dependencies)

`dune fmt` to format the code.(need `.ocamlformat` file)

`dune build` to build the project.

`dune runtest` to run the tests.

`dune utop lib` to run the code in the utop.

## Usage
The default parameters are defined in `types.ml`. You can change the parameters if you want to use different parameters.(default `N` use 2048 bit prime number)

Below there is an example of how to use the SRP protocol to sign up and log in. which using `dune utop lib` to run the code.

Load the modules and initialize the random number generator
```ocaml
open Srp__Types
open Srp__Utils
open Srp__Client
open Srp__Server
let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)
```

### Sign Up
Generate a salt, init the default parameters, and derive the verifier from the password
```ocaml
let d = default_shared_parameters
let username = "MingLLuo"
let password = "deadbeef"
let salt = gen_salt d
let client_derive_param = {
  client_ephemeral_secret = Z.zero;
  server_ephemeral_public = Z.zero;
  salt;
  client_identity = username;
  client_password = password;
}
let privateKey = derive_private_key d client_derive_param
let verifier = derive_verifier d privateKey
```
### Login
1. The client generates a secret/public ephemeral value pair
```ocaml
let client_ephemeral = Srp__Client.gen_ephemeral d
let client_derive_param = {
  client_derive_param with
  client_ephemeral_secret = client_ephemeral.secret;
}
```

2. The server generates a secret/public ephemeral value pair
```ocaml
let server_ephemeral = Srp__Server.gen_ephemeral d verifier
```

3. The client can now derive the shared strong session key, and a proof of it to provide to the server.
```ocaml
let client_derive_param = {
  client_derive_param with
  server_ephemeral_public = server_ephemeral.public;
}
let client_session = Srp__Client.derive_session d client_derive_param
```

4. The server can now verify the client's proof and derive the shared strong session key.
```ocaml
let server_derive_param = {
  server_ephemeral_secret = server_ephemeral.secret;
  client_ephemeral_public = client_ephemeral.public;
  salt;
  client_identity = username;
  verifier;
  client_session_proof = client_session.proof;
}
let server_session = Srp__Server.derive_session d server_derive_param
```

5. Cclient verify that the server have derived the correct strong session key, using the proof that the server sent back. 
```ocaml
let client_verify_param = {
  client_ephemeral = client_ephemeral.public;
  client_session;
  server_session_proof = server_session.proof;
}
let client_session = Srp__Client.verify_session d client_verify_param
```

### Full Example
```ocaml
open Srp__Types
open Srp__Utils
open Srp__Client
open Srp__Server

let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)
let d = default_shared_parameters
let username = "MingLLuo"
let password = "deadbeef"
let salt = gen_salt d

let client_derive_param =
  { client_ephemeral_secret = Z.zero
  ; server_ephemeral_public = Z.zero
  ; salt
  ; client_identity = username
  ; client_password = password
  }
;;

let privateKey = derive_private_key d client_derive_param
let verifier = derive_verifier d privateKey
let client_ephemeral = Srp__Client.gen_ephemeral d

let client_derive_param =
  { client_derive_param with client_ephemeral_secret = client_ephemeral.secret }
;;

let server_ephemeral = Srp__Server.gen_ephemeral d verifier

let client_derive_param =
  { client_derive_param with server_ephemeral_public = server_ephemeral.public }
;;

let client_session = Srp__Client.derive_session d client_derive_param

let server_derive_param =
  { server_ephemeral_secret = server_ephemeral.secret
  ; client_ephemeral_public = client_ephemeral.public
  ; salt
  ; client_identity = username
  ; verifier
  ; client_session_proof = client_session.proof
  }
;;

let server_session = Srp__Server.derive_session d server_derive_param

let client_verify_param =
  { client_ephemeral = client_ephemeral.public
  ; client_session
  ; server_session_proof = server_session.proof
  }
;;

let client_session = Srp__Client.verify_session d client_verify_param

```