defmodule BlsEx do
  alias __MODULE__.Keystore

  @doc """
  Creates a new BLS keystore

  ## Examples

      iex> {:ok, pid} = BlsEx.new_keystore("myseed")
      iex> {:ok, public_key} = BlsEx.Keystore.get_public_key(pid)
      iex> {:ok, signature} = BlsEx.Keystore.sign(pid, "hello")
  """
  @spec new_keystore(binary()) :: GenServer.on_start()
  def new_keystore(seed) do
    Keystore.start_link(seed: seed)
  end

  @doc """
  Verifies a single BLS signature
  """
  @spec verify_signature(public_key :: binary(), message :: binary(), signature :: binary()) ::
          {:ok, boolean()} | {:error, any()}
  defdelegate verify_signature(public_key, message, signature), to: __MODULE__.StandaloneWasm

  @doc """
  Aggregate BLS signatures
  """
  @spec aggregate_signatures(signatures :: list(binary()), public_keys :: list(binary())) ::
          {:ok, binary()} | {:error, any()}
  defdelegate aggregate_signatures(signatures, public_keys), to: __MODULE__.StandaloneWasm

  @doc """
  Aggregate BLS public keys
  """
  @spec aggregated_public_keys(public_keys :: list(binary())) :: {:ok, binary()} | {:error, any()}
  defdelegate aggregated_public_keys(public_keys), to: __MODULE__.StandaloneWasm

  @doc """
  Verifies an aggregated BLS signature
  """
  @spec verify_aggregated_signature(list(binary()), binary(), binary()) ::
          {:ok, boolean()} | {:error, any()}
  defdelegate verify_aggregated_signature(public_keys, message, signature),
    to: __MODULE__.StandaloneWasm

  def test() do
    {:ok, keystore1} = new_keystore("test")
    # {:ok, keystore2} = new_keystore("test2")
    # {:ok, public_key1} = Keystore.get_public_key(keystore1)
    # {:ok, public_key2} = Keystore.get_public_key(keystore2)
    # {:ok, signature1} = Keystore.sign(keystore1, "hello")
    # # # IO.inspect(Base.encode16(signature1))
    # {:ok, signature2} = Keystore.sign(keystore2, "hello")
    # # IO.inspect(Base.encode16(signature2))

    # verify_signature(public_key1, "hello", signature1)
    # #
    # {:ok, agg_signature} =
    #   aggregate_signatures([signature1, signature2], [public_key1, public_key2])

    # # # IO.inspect(Base.encode16(agg_signature))
    # verify_aggregated_signature([public_key1, public_key2], "hello", agg_signature)
  end
end
