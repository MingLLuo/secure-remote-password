val gen_salt : shared_param:Types.shared_parameters -> Z.t

val derive_private_key
  :  shared_param:Types.shared_parameters
  -> derive_param:Types.client_derive_parameter
  -> Z.t

val derive_verifier : shared_param:Types.shared_parameters -> x:Z.t -> Z.t
val gen_ephemeral : shared_param:Types.shared_parameters -> Types.ephemeral

val derive_session
  :  shared_param:Types.shared_parameters
  -> derive_param:Types.client_derive_parameter
  -> Types.session_key

val verify_session
  :  shared_param:Types.shared_parameters
  -> verify_param:Types.client_verify_parameter
  -> bool
