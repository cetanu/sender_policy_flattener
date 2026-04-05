open Cmdliner


let lookup client rr_name rr_type = 
    Printf.printf "  %s %s -- " rr_name (Cfg.string_of_rrtype rr_type);

    let rr = match rr_type with
        | Cfg.A -> Dns.Rr_map.A
        | Cfg.AAAA -> Dns.Rr_map.Aaaa
        | Cfg.CNAME -> Dns.Rr_map.Cname
        | Cfg.MX -> Dns.Rr_map.Mx
        | Cfg.TXT -> Dns.Rr_map.Txt
        | s -> Dns.Rr_map.A
    in
    let _result = Dns_client_unix.get_resource_record client rr rr_name 
    Printf.printf "Result: %s\n" _result in
    ()

let compress name =
    let config = Cfg.load_config name in
    let client = Dns_client_unix.create () in
    Hashtbl.iter (fun sending_domain inner ->
      Printf.printf "\n[%s]\n" sending_domain;
      Hashtbl.iter (lookup client) inner
    ) config



let config_arg =
  let doc = "Location of JSON config file on disk" in
  Arg.(required & pos 0 (some string) None & info [] ~docv:"CONFIG" ~doc)

let spfcompress_t = Term.(const compress $ config_arg )

let info =
  let doc = {|
    A tool to compress ip4 and ip6 addresses from a set of DNS records,
    into a minimal set of TXT records
  |} in
  Cmd.info "spfcompress" ~version:"1.0" ~doc

let parse_args = exit (Cmd.eval (Cmd.v info spfcompress_t))
