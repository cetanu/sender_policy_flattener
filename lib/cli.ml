open Cmdliner


let parse_spf record = 
    let mechanisms = String.split_on_char ' ' record in
    List.filter_map (fun mechanism -> match String.split_on_char ':' mechanism with
    | [k; v] -> (match k with
        | "include" | "a" | "mx" | "ip4" | "ip6" | "exists" -> Some (k, v)
        | _ -> failwith "invalid mechanism")
    | _ -> None
    ) mechanisms 


let lookup client rr_name rr_type = 
    Printf.printf "  %s %s -- " rr_name (Cfg.string_of_rrtype rr_type);
    
    match Domain_name.of_string rr_name with
    | Ok name ->
        (match rr_type with
        | Cfg.A -> 
            let result = Dns_client_unix.get_resource_record client Dns.Rr_map.A name in
            (match result with 
            | Ok (_, ips) ->
                let ip_strs = Ipaddr.V4.Set.fold (fun ip acc -> (Ipaddr.V4.to_string ip) :: acc) ips [] in
                Printf.printf "Result: %s\n" (String.concat ", " ip_strs)
            | Error _ -> Printf.printf "Result: error\n")

        | Cfg.AAAA -> 
            let result = Dns_client_unix.get_resource_record client Dns.Rr_map.Aaaa name in
            (match result with
            | Ok (_, ips) -> 
                let ip_strs = Ipaddr.V6.Set.fold (fun ip acc -> (Ipaddr.V6.to_string ip) :: acc) ips [] in
                Printf.printf "Result: %s\n" (String.concat ", " ip_strs)
            | Error _ -> Printf.printf "Result: error")

        | Cfg.CNAME -> 
            let _result = Dns_client_unix.get_resource_record client Dns.Rr_map.Cname name in
            Printf.printf "Result: %s\n" (match _result with Ok _ -> "ok" | Error _ -> "error")

        | Cfg.MX -> 
            let _result = Dns_client_unix.get_resource_record client Dns.Rr_map.Mx name in
            Printf.printf "Result: %s\n" (match _result with Ok _ -> "ok" | Error _ -> "error")

        | Cfg.TXT -> 
            let result = Dns_client_unix.get_resource_record client Dns.Rr_map.Txt name in
            (match result with
            | Ok (_, texts) ->
                let spf_records = Dns.Rr_map.Txt_set.fold (fun txt acc -> 
                    match txt with
                    | _ when String.starts_with ~prefix:"v=spf" txt  -> 
                            let _ = parse_spf txt in
                            txt :: acc
                    | _ -> acc
            ) texts [] in
                Printf.printf "Result: %s\n" (String.concat " @@@ " spf_records)
            | Error _ -> Printf.printf "Result: error\n"))
    | Error _ -> Printf.printf "Result: invalid domain\n"



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
