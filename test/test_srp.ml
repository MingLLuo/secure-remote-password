open Srp
open Types
open Utils
open Server
open Client

(* Utils test *)
(* 1. randint test *)
let test_randint () =
  let n = Z.of_int 10 in
  let () = Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna) in
  let r = random_bigint n in
  let () = Printf.printf "r: %s\n" (Z.to_string r) in
  Alcotest.(check bool) "randint test" (Z.compare r n < 0) true
;;

(* 2. xor_cstruct test *)
let test_xor_cstruct () =
  let cs1 = Cstruct.of_string "1234" in
  let cs2 = Cstruct.of_string "5678" in
  let result = xor_cstruct cs1 cs2 in
  let () = Printf.printf "result: %s\n" (Cstruct.to_hex_string result) in
  Alcotest.(check string) "xor_cstruct test" (Cstruct.to_hex_string result) "0404040c"
;;

let test_xor_cstruct_fast () =
  let cs1 = Cstruct.of_string "1234" in
  let cs2 = Cstruct.of_string "5678" in
  let expected = xor_cstruct cs1 cs2 in
  let result = xor_cstruct_fast cs1 cs2 in
  let () = Printf.printf "result: %s\n" (Cstruct.to_hex_string result) in
  Alcotest.(check string)
    "xor_cstruct_fast test"
    (Cstruct.to_hex_string result)
    (Cstruct.to_hex_string expected)
;;

(* Server test *)
(* 1. small (kv+g^b) % N *)
let test_kv1 () =
  let shared_param =
    { n = Z.of_int 10
    ; g = Z.of_int 2
    ; k = Z.of_int 3
    ; hash = (module Mirage_crypto.Hash.SHA1)
    ; hash_bytes_size = 20
    }
  in
  let v = Z.of_int 2 in
  let b = Z.of_int 3 in
  let result = compute_kv_plus_gb ~shared_param ~v ~b in
  let () = Printf.printf "result: %s\n" (Z.to_string result) in
  Alcotest.(check string) "kv+gb % N test" (Z.to_string result) "4"
;;

(* 2. large (kv+g^b) % N *)
let test_kv2 () =
  let shared_parameters = default_shared_parameters in
  let open Z in
  let v = (shared_parameters.n - one) * of_int 3 in
  let b = Z.of_string "5" in
  let result = compute_kv_plus_gb ~shared_param:shared_parameters ~v ~b in
  let () = Printf.printf "result: %s\n" (Z.to_string result) in
  Alcotest.(check string) "kv+gb % N test" (Z.to_string result) "23"
;;

(* Client Test  *)
(* 1. derive_private_key test *)
let test_pk () =
  let shared_param = default_shared_parameters in
  let module H = (val shared_param.hash) in
  let open Z in
  let alice =
    { client_ephemeral_secret = zero
    ; server_ephemeral_public = zero
    ; salt = one
    ; client_identity = "alice"
    ; client_password = "password"
    }
  in
  let result = derive_private_key ~shared_param ~derive_param:alice in
  let () = Printf.printf "result: %s\n" (Z.to_string result) in
  let hash_0 = H.digest (Cstruct.of_string "alice:password") in
  let () = print_endline ("hash_0: " ^ Cstruct.to_hex_string hash_0) in
  let x = H.digest (Cstruct.concat [ z_to_cstruct one; hash_0 ]) |> cstruct_to_z in
  let () = print_endline ("x: " ^ Z.to_string x) in
  Alcotest.(check string) "derive_private_key test" (Z.to_string result) (Z.to_string x)
;;

(* 2. derive_verifier test, from mozilla/node-srp a/A_expected *)
let test_dv () =
  let shared_param =
    { default_shared_parameters with
      n =
        Z.of_string_base
          16
          "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
    }
  in
  let a =
    Z.of_string_base 16 "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"
  in
  let expected =
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b"
    |> Z.of_string_base 16
    |> Z.to_string
  in
  let result = derive_verifier ~shared_param ~x:a in
  let () = Printf.printf "result: %s\n" (Z.to_string result) in
  Alcotest.(check string) "derive_verifier test" (Z.to_string result) expected
;;

let () =
  let open Alcotest in
  run
    "test"
    [ ( "utils"
      , [ test_case "randint" `Quick test_randint
        ; test_case "xor_cstruct" `Quick test_xor_cstruct
        ; test_case "xor_cstruct_fast" `Quick test_xor_cstruct_fast
        ] )
    ; ( "server"
      , [ test_case "simple kv+gb % N" `Quick test_kv1
        ; test_case "large kv+gb % N" `Quick test_kv2
        ] )
    ; ( "client"
      , [ test_case "derive_private_key" `Quick test_pk
        ; test_case "derive_verifier" `Quick test_dv
        ] )
    ]
;;
