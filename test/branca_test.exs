defmodule BrancaTest do
  use ExUnit.Case
  doctest Branca

  @token "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a"
  @nonce String.duplicate(<<0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c>>, 2)
  @payload "Hello world!"

  test "Should pass test vector 1" do
    assert Branca.encode(@payload, 123206400, @nonce) == @token
    assert Branca.decode(@token) == {:ok, @payload}
  end

  test "Should encode payload" do
    token = Branca.encode(@payload)
    assert Branca.decode(token) == {:ok, @payload}
  end

  test "Should encode payload and timestamp" do
    token = Branca.encode(@payload, 123206400)
    assert Branca.decode(token) == {:ok, @payload}
  end
end
