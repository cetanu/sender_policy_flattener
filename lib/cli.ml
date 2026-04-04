open Cmdliner

let compress name =
    let config = Cfg.load_config name in
    Hashtbl.iter (fun domain inner ->
      Printf.printf "\n[%s]\n" domain;
      Hashtbl.iter (fun host rr ->
        Printf.printf "  %s %s\n" host (Cfg.string_of_rrtype rr)
      ) inner
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
