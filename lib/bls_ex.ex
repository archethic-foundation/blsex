defmodule BlsEx do
  @moduledoc """
  BlsEx provides utility to leverage BLS signatures

  BLS scheme supports aggregation of public keys and aggregation of signatures.

  Here an full example of aggregated signature verification

      iex> seed = :crypto.hash(:sha512, "myseed")
      iex> public_key1 = BlsEx.get_public_key!(seed)
      iex> signature1 = BlsEx.sign!(seed, "hello")
      iex> seed2 = :crypto.hash(:sha512, "myseed2")
      iex> public_key2 = BlsEx.get_public_key!(seed2)
      iex> signature2 = BlsEx.sign!(seed2, "hello")
      iex> aggregated_signature = BlsEx.aggregate_signatures!([signature1, signature2], [public_key1, public_key2])
      iex> aggregated_public_key = BlsEx.aggregate_public_keys!([public_key1, public_key2])
      iex> BlsEx.verify_signature?(aggregated_public_key, "hello", aggregated_signature)
      true
  """

  # 64 bytes
  @type secret_key :: <<_::512>>
  # 96 bytes
  @type signature :: <<_::768>>
  # 48 bytes
  @type public_key :: <<_::384>>

  alias __MODULE__.Native

  @doc """
  Generate a public key from a secret key
  """
  @spec get_public_key(secret_key :: secret_key()) ::
          {:ok, public_key()} | {:error, :invalid_seed}
  def get_public_key(secret_key) when is_binary(secret_key) and byte_size(secret_key) == 64,
    do: Native.get_public_key(secret_key)

  @doc """
  Same as `get_public_key/1` but raise the error
  """
  @spec get_public_key!(secret_key :: secret_key()) :: public_key()
  def get_public_key!(secret_key) do
    case get_public_key(secret_key) do
      {:ok, public_key} -> public_key
      {:error, :invalid_seed} -> raise "Invalid seed"
    end
  end

  @doc """
  Sign a message using the given secret key
  """
  @spec sign(secret_key :: secret_key(), message :: binary()) ::
          {:ok, signature()} | {:error, :invalid_seed}
  def sign(secret_key, data)
      when is_binary(secret_key) and byte_size(secret_key) == 64 and is_binary(data),
      do: Native.sign(secret_key, data)

  @doc """
  Same as `sign/2` but raise the error
  """
  @spec sign!(secret_key :: secret_key(), message :: binary()) :: signature()
  def sign!(secret_key, data) do
    case sign(secret_key, data) do
      {:ok, public_key} -> public_key
      {:error, :invalid_seed} -> raise "Invalid seed"
    end
  end

  @doc """
  Verifies a single BLS signature
  """
  @spec verify_signature?(
          public_key :: public_key(),
          message :: binary(),
          signature :: signature()
        ) ::
          boolean()
  def verify_signature?(public_key, message, signature)
      when is_binary(public_key) and byte_size(public_key) == 48 and is_binary(message) and
             is_binary(signature) and byte_size(signature) == 96 do
    case Native.verify_signature(public_key, message, signature) do
      {:ok, valid?} -> valid?
      {:error, _} -> false
    end
  end

  @doc """
  Aggregate a list of signatures
  """
  @spec aggregate_signatures(signatures :: list(signature()), public_keys :: list(public_key())) ::
          {:ok, aggregated_signature :: signature()} | {:error, :no_valid_keys_or_signatures}
  def aggregate_signatures(signatures, public_keys)
      when is_list(signatures) and is_list(public_keys) and
             length(signatures) > 0 and length(public_keys) > 0 and
             length(signatures) == length(public_keys) do
    case Native.aggregate_signatures(signatures, public_keys) do
      {:ok, signature} -> {:ok, signature}
      {:error, :zero_size_input} -> {:error, :no_valid_keys_or_signatures}
    end
  end

  @doc """
  Same as `aggregate_signatures/2` but raise the error
  """
  @spec aggregate_signatures!(signatures :: list(signature()), public_keys :: list(public_key())) :: aggregated_signature :: signature()
  def aggregate_signatures!(signatures, public_keys) do
    case aggregate_signatures(signatures, public_keys) do
      {:ok, signature} -> signature
      {:error, :no_valid_keys_or_signatures} -> raise "No valid public keys or signatures"
    end
  end

  @doc """
  Aggregate a list of public keys
  """
  @spec aggregate_public_keys(public_keys :: list(public_key())) :: {:ok, aggregated_public_key :: public_key()} | {:error, :no_valid_keys}
  def aggregate_public_keys(public_keys) when is_list(public_keys) and length(public_keys) > 0 do
    case Native.aggregate_public_keys(public_keys) do
      {:ok, public_key} -> {:ok, public_key}
      {:error, :zero_size_input} -> {:error, :no_valid_keys}
    end
  end

  @doc """
  Same as `aggregate_public_keys/1` but raise the error
  """
  @spec aggregate_public_keys!(public_keys :: list(public_key())) :: aggregated_public_key :: public_key()
  def aggregate_public_keys!(public_keys) do
    case aggregate_public_keys(public_keys) do
      {:ok, public_key} -> public_key
      {:error, :no_valid_keys} -> raise "No valid public keys"
    end
  end
end
