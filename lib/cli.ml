open Cmdliner

let compress name =
    Printf.printf "Hello, %s!\n" name


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
