open Yojson.Safe

type dns_rrtype = 
  | A 
  | AAAA 
  | CNAME 
  | MX 
  | TXT

(** Custom decoder to handle case insensitivity *)
let dns_rrtype_of_yojson json =
  match json with
  | `String s ->
      (match String.lowercase_ascii s with
       | "a"     -> Ok A
       | "aaaa"  -> Ok AAAA
       | "cname" -> Ok CNAME
       | "mx"    -> Ok MX
       | "txt"   -> Ok TXT
       | _       -> Error ("Unknown RR type: " ^ s))
  | _ -> Error "Expected a JSON string for RR type"

(* The rest of the structure remains the same *)
type config_wrapper = {
  sending_domains : (string * (string * dns_rrtype) list) list;
} [@@deriving yojson]

type nested_dns_map = (string, (string, dns_rrtype) Hashtbl.t) Hashtbl.t

let table_of_wrapper (w : config_wrapper) : nested_dns_map =
  let outer_tbl = Hashtbl.create 16 in
  List.iter (fun (domain, records) ->
    let inner_tbl = Hashtbl.create (List.length records) in
    List.iter (fun (subdomain, rr) -> 
      Hashtbl.replace inner_tbl subdomain rr
    ) records;
    Hashtbl.replace outer_tbl domain inner_tbl
  ) w.sending_domains

let load_dns_config filename =
  let json = Yojson.Safe.from_file filename in
  match config_wrapper_of_yojson json with
  | Ok wrapper -> table_of_wrapper wrapper
  | Error msg -> failwith ("Fatal JSON Error: " ^ msg)
