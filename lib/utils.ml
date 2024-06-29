open Types

(* Generate a random big integer within the range of 0 to n-1 *)
let random_bigint n =
  let n_length = Z.numbits n in
  if n_length = 0 then Z.zero else Mirage_crypto_pk.Z_extra.gen n
;;

let random_bigint_size size = random_bigint (Z.pow (Z.of_int 2) size)
let z_to_cstruct z = Mirage_crypto_pk.Z_extra.to_cstruct_be z
let cstruct_to_z c = Mirage_crypto_pk.Z_extra.of_cstruct_be c
let z_to_string z = Z.to_string z

(* XOR two Cstruct values *)
let xor_cstruct_fast cs1 cs2 =
  let len = min (Cstruct.length cs1) (Cstruct.length cs2) in
  let result = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set
      result
      i
      (Char.chr
         (Char.code (Cstruct.get_char cs1 i) lxor Char.code (Cstruct.get_char cs2 i)))
  done;
  Cstruct.of_bytes result
;;

let xor_cstruct cs1 cs2 =
  let z1 = cstruct_to_z cs1 in
  let z2 = cstruct_to_z cs2 in
  z_to_cstruct Z.(z1 lxor z2)
;;

let compute_m_ ~(shared_param : shared_parameters) ~id ~salt ~a ~b ~k_ =
  let module H = (val shared_param.hash : Mirage_crypto.Hash.S) in
  let h_n = shared_param.n |> z_to_cstruct |> H.digest in
  let h_g = shared_param.g |> z_to_cstruct |> H.digest in
  let xor_hn_hg = xor_cstruct h_n h_g in
  let h_id = H.digest (Cstruct.of_string id) in
  H.digest (Cstruct.concat [ xor_hn_hg; h_id; salt; a; b; k_ ]) |> cstruct_to_z
;;
