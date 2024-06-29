open Types

val compute_kv_plus_gb : shared_param:shared_parameters -> v:Z.t -> b:Z.t -> Z.t
val gen_ephemeral : shared_param:shared_parameters -> verifier:Z.t -> ephemeral

val derive_session
  :  shared_param:shared_parameters
  -> derive_parameter:server_derive_parameter
  -> session_key
