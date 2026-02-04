///|
async fn main {
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
  let uri = @url.parse(uri)
  let ssl_opts = @openssl.INIT_LOAD_SSL_STRINGS |
    @openssl.INIT_LOAD_CRYPTO_STRINGS
  if @openssl.init_ssl(ssl_opts) != 1 {
    fail("Failed to initialize OpenSSL")
  }
  let (host, addr) = match uri.host {
    Some(host) =>
      match host {
        Domain(host) => {
          let port = uri.port.unwrap_or(443)
          let addr = @socket.Addr::resolve(host, port=port.to_int())
          (@encoding/utf8.encode(host), addr)
        }
        IPv4(addr) => {
          let addr = addr.to_string()
          let port = uri.port.unwrap_or(443)
          let sockaddr = @socket.Addr::parse("\{addr}:\{port}")
          (@encoding/utf8.encode(addr), sockaddr)
        }
        IPv6(addr) => {
          let addr = addr.to_string()
          let port = uri.port.unwrap_or(443)
          let sockaddr = @socket.Addr::parse("\{addr}:\{port}")
          (@encoding/utf8.encode(addr), sockaddr)
        }
        Opaque(_) => fail("Invalid URI: Unsupported host type")
      }
    None => fail("Invalid URI: Missing authority")
  }
  let ssl_ctx = @openssl.SslCtx::new(@openssl.Tls::client_method())
  ssl_ctx.set_default_verify_paths()
  let tcp = @socket.Tcp::connect(addr)
  defer tcp.close()
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
  println(@encoding/utf8.decode_lossy(response.contents()))
}
