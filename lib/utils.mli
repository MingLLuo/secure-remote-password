val random_bigint : Z.t -> Z.t
val random_bigint_size : int -> Z.t
val z_to_cstruct : Z.t -> Cstruct.t
val cstruct_to_z : Cstruct.t -> Z.t
val z_to_string : Z.t -> string
val xor_cstruct_fast : Cstruct.t -> Cstruct.t -> Cstruct.t
val xor_cstruct : Cstruct.t -> Cstruct.t -> Cstruct.t

val compute_m_
  :  shared_param:Types.shared_parameters
  -> id:string
  -> salt:Cstruct.t
  -> a:Cstruct.t
  -> b:Cstruct.t
  -> k_:Cstruct.t
  -> Z.t
