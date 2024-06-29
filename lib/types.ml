type shared_parameters =
  { n : Z.t
  ; g : Z.t
  ; k : Z.t
  ; hash : (module Mirage_crypto.Hash.S)
  ; hash_bytes_size : int
  }

type ephemeral =
  { secret : Z.t
  ; public : Z.t
  }

type session_key =
  { key : Z.t
  ; proof : Z.t
  }

type server_derive_parameter =
  { server_ephemeral_secret : Z.t
  ; client_ephemeral_public : Z.t
  ; salt : Z.t
  ; client_identity : string
  ; verifier : Z.t
  ; client_session_proof : Z.t
  }

type client_derive_parameter =
  { client_ephemeral_secret : Z.t
  ; server_ephemeral_public : Z.t
  ; salt : Z.t
  ; client_identity : string
  ; client_password : string
  }

type client_verify_parameter =
  { client_ephemeral : Z.t
  ; client_session : session_key
  ; server_session_proof : Z.t
  }

let default_shared_parameters =
  let open Mirage_crypto.Hash in
  { (* |n| = 1024 *)
    (* n =
       Z.of_string_base 16
       "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"; *)
    (* |n| = 2048 *)
    n =
      Z.of_string_base
        16
        ("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
         ^ "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
         ^ "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
         ^ "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
         ^ "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
         ^ "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
         ^ "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
         ^ "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
         ^ "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
         ^ "9E4AFF73")
  ; g = Z.of_string "2"
  ; k = Z.of_string "3"
  ; hash = (module SHA1)
  ; hash_bytes_size = 20
  }
;;

let default_hash =
  let module Hash = (val default_shared_parameters.hash) in
  Hash.digest, Hash.digest_size
;;
