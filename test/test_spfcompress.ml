let () =
  let filename = "../example_config.json" in
  let dns_map = Spfcompress.Cfg.load_dns_config filename in
  Printf.printf "Successfully loaded %d domains from %s\n" 
    (Hashtbl.length dns_map) filename;
  Hashtbl.iter (fun domain inner_tbl ->
    Printf.printf "Domain %s has %d records\n" 
      domain (Hashtbl.length inner_tbl)
  ) dns_map
