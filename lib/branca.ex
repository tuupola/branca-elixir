defmodule Branca do
  @moduledoc """
  Documentation for Branca.
  """
  alias Salty.Aead.Xchacha20poly1305Ietf, as: Xchacha20
  alias Branca.Token, as: Token

  @version 0xBA
  @alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  @base62 BaseX.prepare_module("Base62", @alphabet, 127)
  @key Application.get_env(:branca, :key)

  def encode(payload) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    encode(payload, timestamp)
  end

  def encode(payload, timestamp) do
    timestamp = timestamp |> :binary.encode_unsigned(:big)
    token = %Token{payload: payload, timestamp: timestamp}
      |> generate_nonce
      |> generate_header
      |> seal

      @base62.encode(token.header <> token.ciphertext)
  end

  def encode(payload, timestamp, nonce) do
    timestamp = timestamp |> :binary.encode_unsigned(:big)
    token = %Token{payload: payload, timestamp: timestamp, nonce: nonce}
      |> generate_header
      |> seal

      @base62.encode(token.header <> token.ciphertext)
  end

  def decode(encoded) do
    token = encoded
      |> base62_decode
      |> explode_binary
      |> explode_header
      |> explode_data

    Xchacha20.decrypt_detached(nil, token.ciphertext, token.tag, token.header, token.nonce, @key)
  end

  defp generate_header(token) do
    header = <<@version>> <> token.timestamp <> token.nonce
    %Token{token | header: header}
  end

  defp generate_nonce(token) do
    {_status, nonce} = Salty.Random.buf(Xchacha20.npubbytes())
    %Token{token | nonce: nonce}
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

