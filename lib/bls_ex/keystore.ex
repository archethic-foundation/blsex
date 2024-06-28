defmodule BlsEx.Keystore do
  use GenServer

  @wasm_path Application.compile_env!(:bls_ex, :wasm_path)

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
    {:ok, %{plugin: plugin, seed_fn: fn -> seed end}}
  end

  defp seed_digest(seed), do: :crypto.hash(:sha256, seed)

  def handle_call(:get_public_key, _from, state = %{plugin: plugin, seed_fn: seed_fn}) do
    case Extism.Plugin.call(
           plugin,
           "getPublicKey",
           Base.encode16(seed_fn.())
         ) do
      {:ok, public_key_hex} ->
        {:reply, {:ok, Base.decode16!(public_key_hex, case: :mixed)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:sign, message}, _from, state = %{plugin: plugin, seed_fn: seed_fn}) do
    case Extism.Plugin.call(
           plugin,
           "signData",
           Jason.encode!(%{seed: Base.encode16(seed_fn.()), data: message})
         ) do
      {:ok, signature_hex} ->
        {:reply, {:ok, Base.decode16!(signature_hex, case: :mixed)}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end
end
