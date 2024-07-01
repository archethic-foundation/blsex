defmodule BlsExTest do
  use ExUnit.Case
  use ExUnitProperties

  doctest BlsEx

  property "cryptographic material should work with all seeds" do
    check all(seed <- StreamData.binary()) do
      {:ok, pid} = BlsEx.Keystore.start_link(seed: seed)
      assert {:ok, public_key} = BlsEx.Keystore.get_public_key(pid)
      assert {:ok, signature} = BlsEx.Keystore.sign(pid, "hello")
      assert {:ok, true} = BlsEx.verify_signature(public_key, "hello", signature)
    end
  end
end
