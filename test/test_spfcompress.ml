let () =
  let filename = "../example_config.json" in
  let dns_map = Spfcompress.Cfg.load_config filename in
  Printf.printf "Successfully loaded %d domains from %s\n" 
    (Hashtbl.length dns_map) filename;
  Hashtbl.iter (fun domain inner_tbl ->
    Printf.printf "Domain %s has %d records\n" 
      domain (Hashtbl.length inner_tbl);
    Hashtbl.iter (fun subdomain rr ->
      let rr_str = match rr with
        | Spfcompress.Cfg.A -> "A"
        | AAAA -> "AAAA"
        | CNAME -> "CNAME"
        | MX -> "MX"
        | TXT -> "TXT"
      in
      Printf.printf "  %s: %s\n" subdomain rr_str
    ) inner_tbl
  ) dns_map
