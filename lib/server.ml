open Types
open Utils

(* Function to compute (kv + g^b) % N *)
let compute_kv_plus_gb ~shared_param ~v ~b =
  let n = shared_param.n in
  let g = shared_param.g in
  let k = shared_param.k in
  let gb = Z.powm g b n in
  let kv = Z.mul k v in
  Z.(add kv gb mod n)
;;

(* Function to generate an ephemeral key pair *)
let gen_ephemeral ~shared_param ~verifier =
  let v = verifier in
  let secret = random_bigint_size shared_param.hash_bytes_size in
  let b_ = compute_kv_plus_gb ~shared_param ~v ~b:secret in
  { secret; public = b_ }
;;

(* Function to derive a session key *)
let derive_session ~shared_param ~(derive_parameter : server_derive_parameter) =
  let n = shared_param.n in
  let module H = (val shared_param.hash) in
  let id = derive_parameter.client_identity in
  let salt = derive_parameter.salt |> z_to_cstruct in
  let v = derive_parameter.verifier in
  let b = derive_parameter.server_ephemeral_secret in
  let b_ = compute_kv_plus_gb ~shared_param ~v ~b |> z_to_cstruct in
  let a_z = derive_parameter.client_ephemeral_public in
  let a_ = derive_parameter.client_ephemeral_public |> z_to_cstruct in
  (* Check valid of A *)
  let open Z in
  if a_z mod n = zero then raise (Invalid_argument "a mod n = 0");
  (* Compute u *)
  let u = H.digest (Cstruct.concat [ a_; b_ ]) |> cstruct_to_z in
  (* Compute S = (Av^u)^b *)
  let s_ = Z.powm (a_z * Z.powm v u n) b n |> z_to_cstruct in
  (* Compute K *)
  let k_ = H.digest s_ in
  (* Compute M *)
  let m_ = compute_m_ ~shared_param ~id ~salt ~a:a_ ~b:b_ ~k_ in
  (* Compute proof *)
  let proof = H.digest (Cstruct.concat [ a_; m_ |> z_to_cstruct; k_ ]) |> cstruct_to_z in
  if m_ = derive_parameter.client_session_proof
  then { key = k_ |> cstruct_to_z; proof }
  else failwith "Invalid client's session proof"
;;
