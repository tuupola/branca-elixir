defmodule Branca do
  @moduledoc """
  Branca allows you to generate and verify encrypted API tokens (IETF
  XChaCha20-Poly1305 AEAD). [Branca specification](https://github.com/tuupola/branca-spec)
  defines the external format and encryption scheme of the token to help
  interoperability between userland implementations. Branca is closely based
  on [Fernet](https://github.com/fernet/spec/blob/master/Spec.md).

  Payload in Branca token is an arbitrary sequence of bytes. This means
  payload can be for example a JSON object, plain text string or even binary
  data serialized by [MessagePack](http://msgpack.org/) or [Protocol Buffers](https://developers.google.com/protocol-buffers/).
  """
  alias Salty.Aead.Xchacha20poly1305Ietf, as: Xchacha20
  alias Branca.Token, as: Token

  @version 0xBA
  @alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @base62 BaseX.prepare_module("Base62", @alphabet, 127)
  @key Application.get_env(:branca, :key)

  @doc """
  Returns base62 encoded encrypted token with given payload.

  Token will use current timestamp and generated random nonce. This is what
  you almost always want to use.

      iex> token = Branca.encode("Hello world!")
      875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a
  """
  def encode(payload) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    encode(payload, timestamp)
  end

  @doc """
  Returns base62 encoded encrypted token with given payload and timestamp

  Token will use generated random nonce. You can for example opt-out from
  timestamp by setting it to `0`. You can also adjust for clock skew by
  setting the timestamp few seconds to future.

      iex> token = Branca.encode("Hello world!", 123206400)
      87x85fHpKCLTmXrRJUcPiOiNTBTpG5MpvUg87fbcaqv2uK68iFK3ocTIVIdlrvXTkhA6jvCf3HiW1
  """
  def encode(payload, timestamp) do
    timestamp = timestamp |> :binary.encode_unsigned(:big)
    token = %Token{payload: payload, timestamp: timestamp}
      |> generate_nonce
      |> generate_header
      |> seal

      @base62.encode(token.header <> token.ciphertext)
  end

  @doc """
  Returns base62 encoded encrypted token with given payload, timestamp and nonce.

  This is mostly used for unit testing. If you use this function make sure not
  to reuse the nonce between tokens.

      iex> nonce = Salty.Random.buf(24)
      iex> token = Branca.encode("Hello world!", 123206400, nonce)
      87x85fNayA1e3Zd0mv0nJao0QE3oNUGTuj9gVdEcrX4RKMQ7a9VGziHec52jgMWYobXwsc4mrRM0A
  """
  def encode(payload, timestamp, nonce) do
    timestamp = timestamp |> :binary.encode_unsigned(:big)
    token = %Token{payload: payload, timestamp: timestamp, nonce: nonce}
      |> generate_header
      |> seal

      @base62.encode(token.header <> token.ciphertext)
  end

  @doc """
  Decrypts and verifies the token and returns the payload.

      iex> token = Branca.encode("Hello world!");
      iex> Branca.decode(token)
      {:ok, "Hello world!"}
  """
  def decode(encoded) do
    token = encoded
      |> base62_decode
      |> explode_binary
      |> explode_header
      |> explode_data

    Xchacha20.decrypt_detached(nil, token.ciphertext, token.tag, token.header, token.nonce, @key)
  end

  @doc """
  Decrypts, verifies and checks the timestamp of the token and returns the payload.

      iex> token = Branca.encode("Hello world!", 123206400);
      iex> Branca.decode(token)
      {:ok, "Hello world!"}
      iex> Branca.decode(token, 60)
      {:error, :expired}
  """
  def decode(encoded, ttl) do
    token = encoded
      |> base62_decode
      |> explode_binary
      |> explode_header
      |> explode_data

    payload = Xchacha20.decrypt_detached(nil, token.ciphertext, token.tag, token.header, token.nonce, @key)

    future = token.timestamp + ttl
    unixtime = DateTime.utc_now() |> DateTime.to_unix()

    cond do
      future < unixtime -> {:error, :expired}
      true -> {:ok, payload}
    end
  end

  defp generate_timestamp(token) do
    timestamp =  DateTime.utc_now() |> DateTime.to_unix()
    %Token{token | timestamp: timestamp}
  end

  defp generate_nonce(token) do
    {_status, nonce} = Salty.Random.buf(Xchacha20.npubbytes())
    %Token{token | nonce: nonce}
  end

  defp generate_header(token) do
    header = <<@version>> <> token.timestamp <> token.nonce
    %Token{token | header: header}
  end

  defp base62_decode(encoded) do
    binary = @base62.decode(encoded)
    %Token{binary: binary}
  end

  defp explode_binary(token) do
    %Token{binary: binary} = token
    << header::binary - size(29), data::binary >> = binary
    %Token{token | header: header, data: data}
  end

  defp explode_header(token) do
    %Token{header: header} = token
    << version::8, timestamp::32, nonce::binary - size(24) >> = header
    %Token{token | version: version, timestamp: timestamp, nonce: nonce}
  end

  defp explode_data(token) do
    %Token{data: data} = token
    size = byte_size(data) - 16
    << ciphertext::binary - size(size), tag::binary - size(16) >> = data
    %Token{token | ciphertext: ciphertext, tag: tag}
  end

  defp seal(token) do
    {_status, ciphertext} = Xchacha20.encrypt(token.payload, token.header, nil, token.nonce, @key)
    %Token{token | ciphertext: ciphertext}
  end
end

