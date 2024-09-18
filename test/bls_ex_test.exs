defmodule BlsExTest do
  use ExUnit.Case
  use ExUnitProperties

  doctest BlsEx

  property "cryptographic material should work with all seeds" do
    check all(seed <- StreamData.binary(length: 64)) do
      assert public_key = BlsEx.get_public_key!(seed)
      assert signature = BlsEx.sign!(seed, "hello")
      assert BlsEx.verify_signature?(public_key, "hello", signature)
    end
  end
end
