defmodule BlsEx do
  @moduledoc """
  BlsEx provides utility to leverage BLS signatures through WASM
  """
  alias __MODULE__.Keystore

  @doc """
  Verifies a single BLS signature

  ## Examples

      iex> {:ok, pid} = BlsEx.Keystore.start_link(seed: "myseed")
      iex> {:ok, public_key} = BlsEx.Keystore.get_public_key(pid)
      iex> {:ok, signature} = BlsEx.Keystore.sign(pid, "hello")
      iex> BlsEx.verify_signature(public_key, "hello", signature)
      {:ok, true}
  """
  @spec verify_signature(public_key :: binary(), message :: binary(), signature :: binary()) ::
          {:ok, boolean()} | {:error, any()}
  defdelegate verify_signature(public_key, message, signature), to: __MODULE__.StandaloneWasm

  @doc """
  Aggregate BLS signatures

  ## Examples

      iex> {:ok, pid} = BlsEx.Keystore.start_link(seed: "myseed")
      iex> {:ok, public_key1} = BlsEx.Keystore.get_public_key(pid)
      iex> {:ok, signature1} = BlsEx.Keystore.sign(pid, "hello")
      iex> {:ok, pid2} = BlsEx.Keystore.start_link(seed: "myseed2")
      iex> {:ok, public_key2} = BlsEx.Keystore.get_public_key(pid2)
      iex> {:ok, signature2} = BlsEx.Keystore.sign(pid2, "hello")
      iex> BlsEx.aggregate_signatures([signature1, signature2], [public_key1, public_key2])
  """
  @spec aggregate_signatures(signatures :: list(binary()), public_keys :: list(binary())) ::
          {:ok, binary()} | {:error, any()}
  defdelegate aggregate_signatures(signatures, public_keys), to: __MODULE__.StandaloneWasm

  @doc """
  Aggregate BLS public keys

  ## Examples

      iex> {:ok, pid} = BlsEx.Keystore.start_link(seed: "myseed")
      iex> {:ok, public_key1} = BlsEx.Keystore.get_public_key(pid)
      iex> {:ok, pid2} = BlsEx.Keystore.start_link(seed: "myseed2")
      iex> {:ok, public_key2} = BlsEx.Keystore.get_public_key(pid2)
      iex> {:ok, _aggregated_public_key} = BlsEx.aggregated_public_keys([public_key1, public_key2])
  """
  @spec aggregated_public_keys(public_keys :: list(binary())) :: {:ok, binary()} | {:error, any()}
  defdelegate aggregated_public_keys(public_keys), to: __MODULE__.StandaloneWasm

  @doc """
  Verifies an aggregated BLS signature

  ## Examples

      iex> {:ok, pid} = BlsEx.Keystore.start_link(seed: "myseed")
      iex> {:ok, public_key1} = BlsEx.Keystore.get_public_key(pid)
      iex> {:ok, signature1} = BlsEx.Keystore.sign(pid, "hello")
      iex> {:ok, pid2} = BlsEx.Keystore.start_link(seed: "myseed2")
      iex> {:ok, public_key2} = BlsEx.Keystore.get_public_key(pid2)
      iex> {:ok, signature2} = BlsEx.Keystore.sign(pid2, "hello")
      iex> {:ok, aggregated_signature} = BlsEx.aggregate_signatures([signature1, signature2], [public_key1, public_key2])
      iex> BlsEx.verify_aggregated_signature( [public_key1, public_key2], "hello", aggregated_signature)
      {:ok, true}
  """
  @spec verify_aggregated_signature(list(binary()), binary(), binary()) ::
          {:ok, boolean()} | {:error, any()}
  defdelegate verify_aggregated_signature(public_keys, message, signature),
    to: __MODULE__.StandaloneWasm
end
