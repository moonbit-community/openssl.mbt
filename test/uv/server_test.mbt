// Test with
// curl -k -X POST -d 'Hello, libuv HTTPS Echo Server!' https://localhost:8443

///|
let server_response_header : Bytes = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"

///|
fn server_write(
  poll : @uv.Poll,
  events : @uv.PollEvent,
  tcp : @uv.Tcp,
  ssl : @openssl.Ssl,
  bytes : BytesView,
  errors : Array[Error],
) -> Unit {
  if !events.is_writable() {
    return
  }
  let written = try ssl.write(bytes.data(), bytes.start_offset(), bytes.length())
    catch {
      error => {
        errors.push(error)
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
        tcp.close(() => ())
        return
      }
    } noraise {
      value => value
    }
  let ssl_error = try ssl.get_error(written) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      tcp.close(() => ())
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None => {
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      tcp.close(() => ())
    }
    error => {
      println("SSL write error: \{error}")
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
    }
  }
}

///|
fn server_read(
  poll : @uv.Poll,
  events : @uv.PollEvent,
  client : @uv.Tcp,
  buffer : @buffer.Buffer,
  ssl : @openssl.Ssl,
  errors : Array[Error],
) -> Unit {
  if !events.is_readable() {
    return
  }
  let bytes = Bytes::make(4096, 0)
  let read = try ssl.read(bytes, 0, bytes.length()) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      return
    }
  } noraise {
    value => value
  }
  let ssl_error = try ssl.get_error(read) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None => {
      buffer.write_bytesview(bytes[:read])
      let request = buffer.contents()
      let response = server_response_header + request
      poll.start(
        @uv.PollEvent::writable(),
        (_, events) => server_write(poll, events, client, ssl, response, errors),
        (_, e) => errors.push(e),
      ) catch {
        e => errors.push(e)
      }
    }
    WantRead => ()
    error => {
      println("SSL read error: \{error}")
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
    }
  }
}

///|
fn server_accept(
  poll : @uv.Poll,
  tcp : @uv.Tcp,
  ssl : @openssl.Ssl,
  errors : Array[Error],
) -> Unit {
  let accept_result = try ssl.accept() catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      tcp.close(() => ())
      return
    }
  } noraise {
    value => value
  }
  let ssl_error = try ssl.get_error(accept_result) catch {
    error => {
      errors.push(error)
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      tcp.close(() => ())
      return
    }
  } noraise {
    value => value
  }
  match ssl_error {
    None =>
      poll.start(
        @uv.PollEvent::readable(),
        (_, events) => server_read(
          poll,
          events,
          tcp,
          @buffer.new(),
          ssl,
          errors,
        ),
        (_, e) => errors.push(e),
      ) catch {
        e => errors.push(e)
      }
    WantRead =>
      poll.start(
        @uv.PollEvent::readable(),
        (_, _) => server_accept(poll, tcp, ssl, errors),
        (_, e) => errors.push(e),
      ) catch {
        e => errors.push(e)
      }
    WantWrite =>
      poll.start(
        @uv.PollEvent::writable(),
        (_, _) => server_accept(poll, tcp, ssl, errors),
        (_, e) => errors.push(e),
      ) catch {
        e => errors.push(e)
      }
    error => {
      println("SSL accept error: \{error}")
      poll.stop() catch {
        e => errors.push(e)
      }
      poll.close(() => ())
      tcp.close(() => ())
    }
  }
}

///|
fn server_on_connection(
  server : @uv.Tcp,
  ssl_ctx : @openssl.SslCtx,
  errors : Array[Error],
) -> Unit {
  println("New connection established")
  try {
    let uv = server.loop_()
    let client = @uv.Tcp::new(uv)
    @uv.accept(server, client)
    println(
      "Accepted connection from \{@encoding/utf8.decode_lossy(client.getpeername().ip_name())}",
    )
    let ssl = @openssl.Ssl::new(ssl_ctx)
    if ssl.set_fd(client.os_sock().to_int()) != 1 {
      println("Failed to set socket for SSL")
      return
    }
    ssl.set_accept_state()
    @uv.Poll::socket(uv, client.os_sock()).start(
      @uv.PollEvent::readable(),
      (poll, _) => server_accept(poll, client, ssl, errors),
      (_, e) => errors.push(e),
    ) catch {
      e => errors.push(e)
    }
  } catch {
    e => errors.push(e)
  }
}

///|
fn run_server_test() -> Unit raise {
  let uv = @uv.Loop::new()
  let errors : Array[Error] = []
  if @openssl.init_ssl(
      @openssl.INIT_LOAD_SSL_STRINGS | @openssl.INIT_LOAD_CRYPTO_STRINGS,
    ) !=
    1 {
    println("Failed to initialize OpenSSL")
    return
  }
  let server_method = @openssl.Tls::server_method()
  let ctx = @openssl.SslCtx::new(server_method)
  defer ignore(try? ctx.free())
  println("OpenSSL initialized successfully")
  if ctx.use_certificate_file("server.crt", @openssl.X509Filetype::Pem) != 1 {
    println("Failed to load server certificate")
    return
  }
  println("Loaded server certificate")
  println("Loaded server private key")
  if ctx.use_PrivateKey_file("server.key", @openssl.X509Filetype::Pem) != 1 {
    println("Failed to use server private key")
    return
  }
  println("Server private key set successfully")
  let server = @uv.Tcp::new(uv)
  let address = @uv.ip4_addr("0.0.0.0", 8444)
  server.bind(address, @uv.TcpBindFlags::new())
  println("Server bound to port 8444")
  server.listen(128, server => server_on_connection(server, ctx, errors), (
    _,
    error,
  ) => errors.push(error))
  uv.run(Default)
  for error in errors {
    println("Error: \{error}")
  }
  uv.close()
}

///|
test {
  run_server_test() catch {
    error => fail("Server SSL test failed: \{error}")
  }
}
