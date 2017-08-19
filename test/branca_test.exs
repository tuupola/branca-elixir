defmodule BrancaTest do
  use ExUnit.Case
  #doctest Branca, except: [:moduledoc, encode: 1, encode: 2, encode: 3]

  @token "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"
  @forged "87x8H26DuLJfzToSrJwLLUnritpp2nUQe2bgoiUbx3wGWGbfNibpJOLqNqjvfsIMkKnqClPeJtFp6"
  @version "8AenkwdktKeVVe9e6uIEi0GwL72HMrPF3cFRsqF2DtxJYb0EZ1jDxdu40XgLY6swS9HleC2oAwvn4"

  @nonce String.duplicate(<<0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c>>, 2)
  @payload "Hello world!"

  test "Should encode payload" do
    token = Branca.encode(@payload)
    assert Branca.decode(token) == {:ok, @payload}
  end

  test "Should encode payload and timestamp" do
    token = Branca.encode(@payload, timestamp: 123206400)
    assert Branca.decode(token) == {:ok, @payload}
  end

  test "Should encode and decode payload, timestamp and nonce" do
    assert Branca.encode(@payload, timestamp: 123206400, nonce: @nonce) == @token
    assert Branca.decode(@token) == {:ok, @payload}
  end

  test "Should fail with expired" do
    assert Branca.encode(@payload, timestamp: 123206400, nonce: @nonce) == @token
    assert Branca.decode(@token, %{:ttl => 3600}) == {:error, :expired}
  end

  test "Should encode with ttl" do
    token = Branca.encode(@payload)
    assert Branca.decode(token, %{:ttl => 3600}) == {:ok, "Hello world!"}
  end

  test "Should fail with forged token" do
    assert Branca.decode(@forged, nonce: @nonce) == {:error, :forged}
  end

  test "Should fail with wrong wrong version" do
    assert Branca.decode(@version) == {:error, :wrong_version}
  end
end
