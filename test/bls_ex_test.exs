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

  property "cryptographic material should work with aggregated keys" do
    data = "hello"

    check all(seeds <- random_list_of_seeds()) do
      {public_keys, signatures} =
        seeds
        |> Enum.map(fn seed ->
          signature = BlsEx.sign!(seed, data)
          public_key = BlsEx.get_public_key!(seed)
          {public_key, signature}
        end)
        |> Enum.unzip()

      agg_signature = BlsEx.aggregate_signatures!(signatures, public_keys)
      agg_public_keys = BlsEx.aggregate_public_keys!(public_keys)

      assert BlsEx.verify_signature?(agg_public_keys, data, agg_signature)
    end
  end

  defp random_list_of_seeds() do
    StreamData.list_of(StreamData.binary(length: 64), min_length: 2, max_length: 25)
  end
end
