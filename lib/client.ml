open Types
open Utils

(* Generate salt(random int) in given range(0, 2^hash_bytes_size) *)
let gen_salt ~shared_param =
  let n = shared_param.hash_bytes_size in
  random_bigint_size n
;;

(* Generate private key
   pk = H(salt || H(id || ":" || pw)
*)
let derive_private_key ~shared_param ~derive_param =
  let module H = (val shared_param.hash) in
  let salt = derive_param.salt |> z_to_cstruct in
  let id = derive_param.client_identity in
  let pw = derive_param.client_password in
  let h_id_pw = H.digest (Cstruct.of_string (id ^ ":" ^ pw)) in
  let x = H.digest (Cstruct.concat [ salt; h_id_pw ]) in
  x |> cstruct_to_z
;;

(* Generate verifier: g^x mod n *)
let derive_verifier ~shared_param ~x =
  let n = shared_param.n in
  let g = shared_param.g in
  Z.powm g x n
;;

(* Generate ephemeral key pair *)
let gen_ephemeral ~shared_param =
  let n = shared_param.n in
  let a = random_bigint n in
  let g = shared_param.g in
  let v = Z.powm g a n in
  { secret = a; public = v }
;;

(* client's derive session, output session key and proof *)
let derive_session ~shared_param ~derive_param =
  let n = shared_param.n in
  let g = shared_param.g in
  let k = shared_param.k in
  let module H = (val shared_param.hash) in
  let salt = derive_param.salt |> z_to_cstruct in
  let a = derive_param.client_ephemeral_secret in
  let a_ = Z.powm g a n in
  let b_ = derive_param.server_ephemeral_public in
  let x = derive_private_key ~shared_param ~derive_param in
  let a_check = Z.powm g a n in
  let open Z in
  if a_check mod n = zero
  then raise (Invalid_argument "a_check mod n = 0")
  else (
    let u =
      H.digest (Cstruct.concat [ z_to_cstruct a_check; z_to_cstruct b_ ]) |> cstruct_to_z
    in
    let s_ = Z.powm (b_ - (k * Z.powm g x n)) (a + (u * x)) n in
    let k_ = H.digest (z_to_cstruct s_) in
    let m_ =
      compute_m_
        ~shared_param
        ~id:derive_param.client_identity
        ~salt
        ~a:(z_to_cstruct a_)
        ~b:(z_to_cstruct b_)
        ~k_
    in
    { key = k_ |> cstruct_to_z; proof = m_ })
;;

(* client's verify session, verify server's proof *)
let verify_session ~shared_param ~verify_param =
  let module H = (val shared_param.hash) in
  let a_ = verify_param.client_ephemeral in
  let m_ = verify_param.client_session.proof in
  let k_ = verify_param.client_session.key in
  let expected =
    H.digest (Cstruct.concat [ z_to_cstruct a_; z_to_cstruct m_; z_to_cstruct k_ ])
  in
  let actual = verify_param.server_session_proof |> z_to_cstruct in
  if Cstruct.equal expected actual then true else false
;;
