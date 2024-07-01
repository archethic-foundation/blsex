defmodule BlsEx.Keystore do
  @doc """
  Represents a keystore holding a the wasm instance for the given private key

  To use the keystore, you have to instanciate it with `start_link/1` and later use either `sign/2` or `get_public_key/1`

  ## Examples

      iex> {:ok, pid} = BlsEx.Keystore.start_link(seed: "myseed")
      iex> {:ok, _signature} = BlsEx.Keystore.sign(pid, "hello")
  """

  use GenServer

  @wasm_path Application.compile_env!(:bls_ex, :wasm_path)

  @type options :: [seed: binary()]

  @doc """
  Start a new keystore instance.

  It requires to pass a keyword list options:
  - `seed`: The private key entropy used to generate public key and sign data
  """
  @spec start_link(options) :: GenServer.on_start()
  def start_link(arg \\ []) do
    GenServer.start_link(__MODULE__, arg)
  end

  @doc """
  Retrieves BLS public key
  """
  @spec get_public_key(keystore_server :: GenServer.server()) :: {:ok, binary()} | {:error, any()}
  def get_public_key(server) do
    GenServer.call(server, :get_public_key)
  end

  @doc """
  Signs a message
  """
  @spec sign(keystore_server :: GenServer.server(), message :: binary()) ::
          {:ok, binary()} | {:error, any()}
  def sign(server, message) do
    GenServer.call(server, {:sign, message})
  end

  def init(arg) do
    seed = Keyword.fetch!(arg, :seed) |> seed_digest()
    bytes = File.read!(@wasm_path) |> Base.encode64()

    manifest = %{
      wasm: [
        %{
          data: bytes
        }
      ]
    }

    {:ok, plugin} = Extism.Plugin.new(manifest)

    {:ok,
     %{
       plugin: plugin,
       seed: seed
     }}
  end

  defp seed_digest(seed), do: :crypto.hash(:sha512, seed)

  def handle_call(:get_public_key, _from, state = %{plugin: plugin, seed: seed}) do
    case Extism.Plugin.call(
           plugin,
           "getPublicKey",
           Base.encode16(seed)
         ) do
      {:ok, public_key_hex} ->
        {:reply, {:ok, Base.decode16!(public_key_hex, case: :mixed)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:sign, message}, _from, state = %{plugin: plugin, seed: seed}) do
    case Extism.Plugin.call(
           plugin,
           "signData",
           Jason.encode!(%{seed: Base.encode16(seed), data: message})
         ) do
      {:ok, signature_hex} ->
        {:reply, {:ok, Base.decode16!(signature_hex, case: :mixed)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end
end
