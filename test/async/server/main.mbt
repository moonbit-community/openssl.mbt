///|
let response : Bytes = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"

///|
fn main {
  try {
    let parser = @clap.Parser::new(args={
      "port": @clap.Arg::named(
        nargs=AtMost(1),
        short='p',
        help="Port to listen on",
      ),
    })
    let value = @clap.SimpleValue::new(parser.prog)
    let help = parser.parse(value, @env.args()[1:])
    if help is Some(help) {
      println(help)
      return
    }
    let port = match value.args.get("port") {
      Some([.., port]) => @strconv.parse_int(port, base=10)
      _ => 8443
    }
    if @openssl.init_ssl(
        @openssl.INIT_LOAD_SSL_STRINGS | @openssl.INIT_LOAD_CRYPTO_STRINGS,
      ) !=
      1 {
      fail("Failed to initialize OpenSSL")
    }
    let ctx = @openssl.SslCtx::new(@openssl.Tls::server_method())
    if ctx.use_certificate_file("../server.crt", @openssl.X509Filetype::Pem) !=
      1 {
      fail("Failed to load server certificate")
    }
    if ctx.use_PrivateKey_file("../server.key", @openssl.X509Filetype::Pem) != 1 {
      fail("Failed to load server private key")
    }
    @async.with_event_loop(_ => {
      let server = @socket.TCP::new()
      defer server.close()
      let addr = @socket.Addr::parse("127.0.0.1:\{port}")
      server.bind(addr)
      server.listen()
      let (client, address) = server.accept()
      defer client.close()
      let ssl = @ssl.Ssl::new(ctx, client)
      ssl.ssl.set_accept_state()
      ssl.accept()
      println("Accepted new connection from \{address}")
      let request = @buffer.new()
      ssl.read_all(request)
      let request = request.contents()
      println(request |> @encoding.decode(encoding=UTF8))
      let response = response + request
      ssl.write_all(response, 0, response.length())
      println("Written \{response.length()} to client")
    })
  } catch {
    error => println("Error: \{error}")
  }
}
