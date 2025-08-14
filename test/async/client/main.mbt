///|
fn main {
  try {
    let parser = @clap.Parser::new(args={
      "uri": @clap.Arg::positional(nargs=One, help="The URI to curl"),
    })
    let value = @clap.SimpleValue::new(parser.prog)
    let help = parser.parse(value, @env.args()[1:])
    if help is Some(help) {
      println(help)
      return
    }
    let uri = match value.positional_args {
      [] => fail("Missing required argument: uri")
      [uri] => uri
      [..] => fail("Too many arguments provided for: uri")
    }
    let uri = match @uri.parse_uri(uri) {
      Ok(uri) => uri
      Err(error) => fail("Failed to parse URI: \{error}")
    }
    let ssl_opts = @openssl.INIT_LOAD_SSL_STRINGS |
      @openssl.INIT_LOAD_CRYPTO_STRINGS
    if @openssl.init_ssl(ssl_opts) != 1 {
      fail("Failed to initialize OpenSSL")
    }
    @async.with_event_loop(_ => {
      let (host, addr) = match uri.authority {
        Some(authority) =>
          match authority.host {
            RegName(host) => {
              let host = @encoding.encode(host, encoding=UTF8)
              let port = authority.port.unwrap_or(443)
              let addr = @socket.Addr::resolve(host, port~)
              (host, addr)
            }
            IPv4(addr) | IPv6(addr) | IPvFuture(addr) => {
              let addr = @encoding.encode(addr, encoding=UTF8)
              let port = match authority.port {
                Some(port) => port
                None => 443
              }
              let sockaddr = @socket.Addr::parse("\{addr}:\{port}")
              (addr, sockaddr)
            }
          }
        None => fail("Invalid URI: Missing authority")
      }
      let ssl_ctx = @openssl.SslCtx::new(@openssl.Tls::client_method())
      ssl_ctx.set_default_verify_paths()
      let tcp = @socket.TCP::new()
      defer tcp.close()
      tcp.connect(addr)
      let ssl = @ssl.Ssl::new(ssl_ctx, tcp)
      if ssl.ssl.set_tlsext_host_name(host) != 1 {
        fail("Failed to set TLS SNI hostname")
      }
      if ssl.ssl.set1_host(host) != 1 {
        fail("Failed to set TLS host")
      }
      ssl.connect()
      let request = @buffer.new()
      request.write_bytes("GET / HTTP/1.1\r\n")
      request.write_bytes("Host: ")
      request.write_bytes(host)
      request.write_bytes("\r\n")
      request.write_bytes("User-Agent: curl/8.7.1\r\n")
      request.write_bytes("Accept: */*\r\n")
      request.write_bytes("Connection: close\r\n")
      request.write_bytes("\r\n")
      let request = request.contents()
      ssl.write_all(request, 0, request.length())
      let response = @buffer.new()
      ssl.read_all(response)
      println(response.contents() |> @encoding.decode(encoding=UTF8))
    })
  } catch {
    error => println("Error: \{error}")
  }
}
