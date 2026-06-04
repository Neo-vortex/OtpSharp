namespace OtpSharper.Core;

/// <summary>
/// Abstracts the current UTC time source. Enables testing and NTP-corrected time sources.
/// </summary>
public interface ITimeProvider
{
    /// <summary>Gets the current UTC time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>
/// Default time provider that delegates to <see cref="DateTimeOffset.UtcNow"/>.
/// </summary>
public sealed class SystemTimeProvider : ITimeProvider
{
    /// <summary>Singleton instance.</summary>
    public static readonly SystemTimeProvider Instance = new();

    private SystemTimeProvider() { }

    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>
/// A time provider with a fixed offset applied to the system clock.
/// Useful for correcting known clock drift without NTP.
/// </summary>
public sealed class OffsetTimeProvider : ITimeProvider
{
    private readonly TimeSpan _offset;

    /// <summary>
    /// Creates an offset-adjusted time provider.
    /// </summary>
    /// <param name="offset">
    /// Positive = system clock is behind (add offset).
    /// Negative = system clock is ahead (subtract offset).
    /// </param>
    public OffsetTimeProvider(TimeSpan offset) => _offset = offset;

    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow + _offset;
}

/// <summary>
/// A time provider with a fixed absolute time. For unit tests only.
/// </summary>
public sealed class FixedTimeProvider : ITimeProvider
{
    private readonly DateTimeOffset _fixedTime;

    /// <summary>Creates a fixed time provider.</summary>
    public FixedTimeProvider(DateTimeOffset fixedTime) => _fixedTime = fixedTime;

    /// <inheritdoc />
    public DateTimeOffset UtcNow => _fixedTime;
}

/// <summary>
/// Provides Unix epoch time utilities.
/// </summary>
public static class UnixTime
{
    /// <summary>Unix epoch: 1970-01-01T00:00:00Z.</summary>
    public static readonly DateTimeOffset UnixEpoch = DateTimeOffset.UnixEpoch;

    /// <summary>
    /// Returns the number of whole seconds since the given epoch.
    /// </summary>
    public static long SecondsSince(DateTimeOffset epoch, DateTimeOffset now)
        => (long)(now - epoch).TotalSeconds;

    /// <summary>
    /// Computes the TOTP counter (time step) for the given parameters.
    /// </summary>
    /// <param name="now">Current time.</param>
    /// <param name="stepSeconds">Time step in seconds.</param>
    /// <param name="epoch">Custom epoch (default: Unix epoch).</param>
    public static long GetCounter(DateTimeOffset now, int stepSeconds, DateTimeOffset? epoch = null)
    {
        long elapsed = SecondsSince(epoch ?? UnixEpoch, now);
        return elapsed / stepSeconds;
    }

    /// <summary>
    /// Returns how many seconds remain in the current time step window.
    /// </summary>
    public static int RemainingSeconds(DateTimeOffset now, int stepSeconds, DateTimeOffset? epoch = null)
    {
        long elapsed = SecondsSince(epoch ?? UnixEpoch, now);
        return stepSeconds - (int)(elapsed % stepSeconds);
    }

    /// <summary>
    /// Returns when the current time step window expires.
    /// </summary>
    public static DateTimeOffset StepExpiry(DateTimeOffset now, int stepSeconds, DateTimeOffset? epoch = null)
        => now.AddSeconds(RemainingSeconds(now, stepSeconds, epoch));
}
