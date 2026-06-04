namespace OtpSharper.Hotp;

/// <summary>
/// Abstraction for persisting HOTP counter state.
/// </summary>
/// <remarks>
/// HOTP counter storage must be durable and atomic. The implementation
/// must guarantee that once a counter is advanced, the old value is
/// never accepted again — even across process restarts.
/// </remarks>
public interface IHotpCounterStore
{
    /// <summary>
    /// Gets the current counter value for the given key identifier.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key/user.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask<long> GetCounterAsync(string keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically advances the counter to <paramref name="newCounter"/>.
    /// Must be a no-op if <paramref name="newCounter"/> ≤ current.
    /// </summary>
    /// <param name="keyId">Unique identifier for the key/user.</param>
    /// <param name="newCounter">The new counter value (must be strictly greater than current).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask SetCounterAsync(string keyId, long newCounter, CancellationToken cancellationToken = default);
}

/// <summary>
/// Thread-safe in-memory HOTP counter store.
/// </summary>
/// <remarks>
/// Suitable for development/testing. Not persistent — state is lost on restart.
/// For production, implement <see cref="IHotpCounterStore"/> with a database.
/// </remarks>
public sealed class InMemoryHotpCounterStore : IHotpCounterStore
{
    private readonly Dictionary<string, long> _counters = [];
    private readonly Lock _lock = new();

    /// <inheritdoc />
    public ValueTask<long> GetCounterAsync(string keyId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_lock)
        {
            return ValueTask.FromResult(_counters.GetValueOrDefault(keyId, 0L));
        }
    }

    /// <inheritdoc />
    public ValueTask SetCounterAsync(string keyId, long newCounter, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        lock (_lock)
        {
            long current = _counters.GetValueOrDefault(keyId, 0L);
            if (newCounter > current)
                _counters[keyId] = newCounter;
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>Resets all counters (for testing only).</summary>
    public void Reset()
    {
        lock (_lock) { _counters.Clear(); }
    }

    /// <summary>Returns the number of tracked keys.</summary>
    public int Count
    {
        get { lock (_lock) { return _counters.Count; } }
    }
}
