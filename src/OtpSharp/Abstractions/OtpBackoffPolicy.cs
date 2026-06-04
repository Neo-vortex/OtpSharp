using System.Collections.Concurrent;

namespace OtpSharp.Abstractions;

/// <summary>
/// Configuration for OTP brute-force protection.
/// </summary>
public sealed class OtpBackoffOptions
{
    /// <summary>Maximum failed attempts before lockout. Default: 5.</summary>
    public int MaxFailedAttempts { get; init; } = 5;

    /// <summary>
    /// Duration of the lockout after <see cref="MaxFailedAttempts"/> are exceeded.
    /// Default: 15 minutes.
    /// </summary>
    public TimeSpan LockoutDuration { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Window in which failed attempts are counted.
    /// Attempts older than this are forgotten.
    /// Default: 10 minutes.
    /// </summary>
    public TimeSpan AttemptWindow { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// When <c>true</c>, successful validation resets the failure count.
    /// Default: <c>true</c>.
    /// </summary>
    public bool ResetOnSuccess { get; init; } = true;
}

/// <summary>
/// Result of an OTP attempt through the backoff policy.
/// </summary>
public sealed class BackoffResult
{
    private BackoffResult(bool allowed, bool lockedOut, int failedAttempts,
        int remainingAttempts, DateTimeOffset? lockoutExpiry)
    {
        IsAllowed        = allowed;
        IsLockedOut      = lockedOut;
        FailedAttempts   = failedAttempts;
        RemainingAttempts = remainingAttempts;
        LockoutExpiry    = lockoutExpiry;
    }

    /// <summary>The attempt was allowed (not locked out).</summary>
    public bool IsAllowed { get; }

    /// <summary>The key is currently locked out.</summary>
    public bool IsLockedOut { get; }

    /// <summary>Number of failed attempts recorded in the window.</summary>
    public int FailedAttempts { get; }

    /// <summary>Remaining attempts before lockout triggers.</summary>
    public int RemainingAttempts { get; }

    /// <summary>When the lockout expires. Null if not locked out.</summary>
    public DateTimeOffset? LockoutExpiry { get; }

    internal static BackoffResult Locked(int failed, DateTimeOffset expiry)
        => new(false, true, failed, 0, expiry);

    internal static BackoffResult Allowed(int failed, int remaining)
        => new(true, false, failed, remaining, null);
}

/// <summary>
/// Thread-safe in-memory brute-force protection for OTP validation.
/// Tracks failed attempts per key ID and applies lockout policies.
/// </summary>
/// <remarks>
/// For production systems, replace the in-memory store with a distributed cache
/// (Redis, etc.) by implementing the same logic against your cache layer.
/// This class is suitable for single-server deployments.
/// </remarks>
public sealed class OtpBackoffPolicy
{
    private sealed record AttemptRecord(DateTimeOffset Timestamp);
    private sealed class KeyState
    {
        public readonly List<AttemptRecord> Attempts = [];
        public DateTimeOffset? LockoutUntil;
    }

    private readonly ConcurrentDictionary<string, KeyState> _states = new();
    private readonly OtpBackoffOptions _options;

    /// <summary>Creates a backoff policy with default options.</summary>
    public OtpBackoffPolicy() : this(new OtpBackoffOptions()) { }

    /// <summary>Creates a backoff policy with the given options.</summary>
    public OtpBackoffPolicy(OtpBackoffOptions options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Checks whether the key is allowed to attempt validation right now.
    /// Call this BEFORE validating.
    /// </summary>
    public BackoffResult CheckAllowed(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        var state = _states.GetOrAdd(keyId, _ => new KeyState());
        lock (state)
        {
            Prune(state);

            if (state.LockoutUntil.HasValue && DateTimeOffset.UtcNow < state.LockoutUntil)
                return BackoffResult.Locked(state.Attempts.Count, state.LockoutUntil.Value);

            int failed    = state.Attempts.Count;
            int remaining = Math.Max(0, _options.MaxFailedAttempts - failed);
            return BackoffResult.Allowed(failed, remaining);
        }
    }

    /// <summary>
    /// Records a failed validation attempt.
    /// If the failure threshold is reached, the key is locked out.
    /// </summary>
    public BackoffResult RecordFailure(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        var state = _states.GetOrAdd(keyId, _ => new KeyState());
        lock (state)
        {
            Prune(state);
            state.Attempts.Add(new AttemptRecord(DateTimeOffset.UtcNow));

            if (state.Attempts.Count >= _options.MaxFailedAttempts)
            {
                state.LockoutUntil = DateTimeOffset.UtcNow + _options.LockoutDuration;
                return BackoffResult.Locked(state.Attempts.Count, state.LockoutUntil.Value);
            }

            int remaining = Math.Max(0, _options.MaxFailedAttempts - state.Attempts.Count);
            return BackoffResult.Allowed(state.Attempts.Count, remaining);
        }
    }

    /// <summary>
    /// Records a successful validation. Resets failure count if configured to do so.
    /// </summary>
    public void RecordSuccess(string keyId)
    {
        if (!_options.ResetOnSuccess) return;
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        if (_states.TryGetValue(keyId, out var state))
        {
            lock (state)
            {
                state.Attempts.Clear();
                state.LockoutUntil = null;
            }
        }
    }

    /// <summary>
    /// Manually unlocks a key (e.g., after admin intervention).
    /// </summary>
    public void Unlock(string keyId)
    {
        if (_states.TryGetValue(keyId, out var state))
        {
            lock (state)
            {
                state.Attempts.Clear();
                state.LockoutUntil = null;
            }
        }
    }

    /// <summary>
    /// Returns whether the key is currently locked out.
    /// </summary>
    public bool IsLockedOut(string keyId)
    {
        if (!_states.TryGetValue(keyId, out var state)) return false;
        lock (state)
        {
            return state.LockoutUntil.HasValue && DateTimeOffset.UtcNow < state.LockoutUntil;
        }
    }

    /// <summary>
    /// Removes all stale entries (keys with no recent activity).
    /// Call periodically to prevent unbounded memory growth.
    /// </summary>
    public void Cleanup()
    {
        foreach (var (key, state) in _states)
        {
            lock (state)
            {
                Prune(state);
                bool expired = !state.LockoutUntil.HasValue
                               || DateTimeOffset.UtcNow >= state.LockoutUntil;
                if (state.Attempts.Count == 0 && expired)
                    _states.TryRemove(key, out _);
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void Prune(KeyState state)
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - _options.AttemptWindow;
        state.Attempts.RemoveAll(a => a.Timestamp < cutoff);

        // Clear expired lockouts
        if (state.LockoutUntil.HasValue && DateTimeOffset.UtcNow >= state.LockoutUntil)
            state.LockoutUntil = null;
    }
}
