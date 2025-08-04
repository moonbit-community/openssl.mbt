///|
let request : Bytes = "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"

///|
fn on_poll(
  poll : @uv.Poll,
  events : @uv.PollEvent,
  tcp : @uv.Tcp,
  ssl : @openssl.Ssl,
  errors : Array[Error],
  buffer : @buffer.T,
) -> Unit {
  if events.is_readable() {
    let bytes = Bytes::make(4096, 0)
    let read = ssl.read(bytes, bytes.length())
    match ssl.get_error(read) {
      None => {
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
        buffer.write_bytesview(bytes[:read])
        tcp.close(() => ())
      }
      WantRead => ()
      WantWrite => ()
      error => {
        println("SSL read error: \{error}")
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
      }
    }
  } else if events.is_writable() {
    let written = ssl.write(request, request.length())
    match ssl.get_error(written) {
      None => {
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.start(
          @uv.PollEvent::readable(),
          (_, events) => on_poll(poll, events, tcp, ssl, errors, buffer),
          (_, e) => errors.push(e),
        ) catch {
          e => errors.push(e)
        }
      }
      WantRead => ()
      WantWrite => ()
      error => {
        println("SSL read error: \{error}")
        poll.stop() catch {
          e => errors.push(e)
        }
        poll.close(() => ())
      }
    }
  }
}

///|
test {
  let uv = @uv.Loop::new()
  let host : Bytes = "www.example.com"
  let port : Bytes = "443"
  let hints = @uv.AddrInfoHints::new()
  let mut addr = None
  let _ = uv.getaddrinfo(
    infos => for info in infos {
      addr = Some(info.addr())
    },
    error => println("Error: \{(error : Error)}"),
    host,
    port,
    hints~,
  )
  uv.run(Default)
  guard addr is Some(addr) else {
    println("Failed to resolve address for \{host}:\{port}")
    return
  }
  let client = @uv.Tcp::new(uv)
  client.connect(addr, () => println("Connected to server"), error => println(
    "Connect error: \{(error : Error)}",
  ))
  |> ignore()
  uv.run(Default)
  if @openssl.init_ssl(
      @openssl.INIT_LOAD_SSL_STRINGS | @openssl.INIT_LOAD_CRYPTO_STRINGS,
      @c.null(),
    ) !=
    1 {
    println("Failed to initialize OpenSSL")
    return
  }
  let store = @openssl.X509Store::new()
  {
    let bio = @openssl.Bio::new_mem_buf(
      @test.mozilla_ca_bundle,
      @test.mozilla_ca_bundle.length(),
    )
    defer bio.free()
    let cert = @openssl.Pem::read_bio_x509(
      bio,
      @c.Nullable::none(),
      @c.null(),
      @c.null(),
    )
    defer cert.free()
    store.add_cert(cert) |> ignore()
  }
  let method_ = @openssl.Tls::client_method()
  let ctx = @openssl.SslCtx::new(method_)
  defer ctx.free()
  ctx.set_cert_store(store) |> ignore()
  let fd = client.fileno().to_int()
  println("Socket created with fd: \{fd}")
  let ssl = @openssl.Ssl::new(ctx)
  defer ssl.free()
  let result = @openssl.Ssl::set_fd(ssl, fd)
  println("SSL set fd result: \{result}")
  let _ = @openssl.Ssl::connect(ssl)
  let written = @openssl.Ssl::write(ssl, request, request.length())
  let poller = @uv.Poll::file(uv, @uv.File::of_int(fd))
  let errors = []
  let buffer = @buffer.new()
  match @openssl.Ssl::get_error(ssl, written) {
    WantRead => {
      poller.start(
        @uv.PollEvent::readable() | @uv.PollEvent::writable(),
        (_, events) => on_poll(poller, events, client, ssl, errors, buffer),
        (_, e) => errors.push(e),
      )
      uv.run(Default)
      let string = @encoding.decode_lossy(buffer.contents(), encoding=UTF8)
      println("Response: \{string}")
      uv.close()
    }
    error => {
      println("SSL error: \{error}")
      @openssl.Ssl::free(ssl)
      @openssl.SslCtx::free(ctx)
      return
    }
  }
}
