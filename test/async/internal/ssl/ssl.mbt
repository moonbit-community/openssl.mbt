///|
fn bytes_to_fixed_array_byte(bytes : Bytes) -> FixedArray[Byte] = "%identity"

///|
fn fixed_array_byte_to_bytes(fixed_array : FixedArray[Byte]) -> Bytes = "%identity"

///|
async fn Ssl::send(self : Ssl) -> Unit {
  let len = self.wbio.read(self.bytes, 0, self.bytes.length())
  self.tcp.write(self.bytes[:len])
}

///|
async fn Ssl::recv(self : Ssl) -> Unit {
  let bytes = bytes_to_fixed_array_byte(self.bytes)
  let len = self.tcp.read(bytes, offset=0, max_len=bytes.length())
  let bytes = fixed_array_byte_to_bytes(bytes)
  if self.rbio.write(bytes, 0, len) < len {
    fail("Failed to write to SSL BIO")
  }
}

///|
pub struct Ssl {
  tcp : @socket.Tcp
  ssl : @openssl.Ssl
  rbio : @openssl.Bio
  wbio : @openssl.Bio
  bytes : Bytes
}

///|
pub fn Ssl::new(ctx : @openssl.SslCtx, tcp : @socket.Tcp) -> Ssl raise {
  let ssl = @openssl.Ssl::new(ctx)
  let bio_s_mem = @openssl.Bio::s_mem()
  let rbio = @openssl.Bio::new(bio_s_mem)
  let wbio = @openssl.Bio::new(bio_s_mem)
  if ssl.set_bio(rbio, wbio) != 1 {
    fail("Failed to set BIO for SSL")
  }
  let bytes = Bytes::make(4096, 0)
  { tcp, ssl, rbio, wbio, bytes }
}

///|
pub async fn Ssl::connect(self : Ssl) -> Unit {
  loop self.ssl.get_error(self.ssl.connect()) {
    None => ()
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      continue self.ssl.get_error(self.ssl.connect())
    }
    WantWrite => {
      self.send()
      continue self.ssl.get_error(self.ssl.connect())
    }
    error => fail("SSL connect error: \{error}")
  }
}

///|
pub async fn Ssl::write_all(
  self : Ssl,
  buffer : Bytes,
  offset : Int,
  length : Int,
) -> Unit {
  let written = self.ssl.write(buffer, offset, length)
  match self.ssl.get_error(written) {
    None => {
      self.send()
      if written < length {
        self.write_all(buffer, offset + written, length - written)
      }
    }
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      self.write_all(buffer, offset, length)
    }
    WantWrite => {
      self.send()
      self.write_all(buffer, offset, length)
    }
    error => fail("SSL write error: \{error}")
  }
}

///|
pub async fn Ssl::read_all(self : Ssl, buffer : @buffer.Buffer) -> Unit {
  let read = self.ssl.read(self.bytes, 0, self.bytes.length())
  match self.ssl.get_error(read) {
    None => {
      buffer.write_bytesview(self.bytes[:read])
      self.read_all(buffer)
    }
    ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      self.read_all(buffer)
    }
    WantWrite => {
      self.send()
      self.read_all(buffer)
    }
    error => fail("SSL read error: \{error}")
  }
}

///|
pub async fn Ssl::accept(self : Ssl) -> Unit {
  match self.ssl.get_error(self.ssl.accept()) {
    None | ZeroReturn => ()
    WantRead => {
      self.send()
      self.recv()
      self.accept()
    }
    WantWrite => {
      self.send()
      self.accept()
    }
    error => fail("SSL accept error: \{error}")
  }
}
