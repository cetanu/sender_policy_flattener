open Yojson.Safe.Util

type rrtype =
  | A
  | AAAA
  | CNAME
  | MX
  | TXT

let rrtype_to_string = function
  | "a" -> A
  | "aaaa" -> AAAA 
  | "cname" -> CNAME
  | "mx" -> MX 
  | "txt" -> TXT
  | s -> failwith ("Unknown RR type: " ^ s)

let string_of_rrtype = function
  | A -> "A" 
  | AAAA -> "AAAA" 
  | CNAME -> "CNAME"
  | MX -> "MX" 
  | TXT -> "TXT"

type sending_domains = (string, (string, rrtype) Hashtbl.t) Hashtbl.t

let parse_record table (rr_name, rr_type) =
  Hashtbl.replace table rr_name
    (rrtype_to_string (String.lowercase_ascii (to_string rr_type)))

let parse_sending_domain table (domain_key, records) =
  let inner = Hashtbl.create 8 in
  List.iter (parse_record inner) (to_assoc records);
  Hashtbl.replace table domain_key inner

let load_config filename =
  let json = Yojson.Safe.from_file filename in
  let tbl = Hashtbl.create 16 in
  let domains = json |> member "sending_domains" |> to_assoc in
  List.iter (parse_sending_domain tbl) domains;
  tbl
