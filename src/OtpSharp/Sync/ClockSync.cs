using System.Net;
using System.Net.Sockets;
using OtpSharp.Core;

namespace OtpSharp.Sync;

/// <summary>
/// Utilities for measuring and correcting system clock drift relative to NTP servers.
/// </summary>
/// <remarks>
/// TOTP is sensitive to clock drift. A drift beyond the validation window will cause
/// authentication failures. This class provides:
/// <list type="bullet">
///   <item>NTP time query (async, no external libraries)</item>
///   <item>Drift measurement</item>
///   <item>Creating a corrected <see cref="ITimeProvider"/></item>
/// </list>
/// </remarks>
public static class ClockSync
{
    // Pool.ntp.org defaults
    private static readonly string[] DefaultNtpServers =
    [
        "pool.ntp.org",
        "time.google.com",
        "time.cloudflare.com",
        "time.windows.com",
    ];

    private const int NtpPort        = 123;
    private const int NtpPacketSize  = 48;
    private const uint NtpEpochOffset = 2_208_988_800; // seconds from 1900 to 1970

    // ── NTP Query ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Queries an NTP server and returns the current UTC time.
    /// </summary>
    /// <param name="server">NTP server hostname. Default: pool.ntp.org</param>
    /// <param name="timeout">Socket timeout. Default: 5 seconds.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">If the NTP query fails.</exception>
    public static async Task<DateTimeOffset> GetNtpTimeAsync(
        string? server = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        server ??= DefaultNtpServers[0];
        timeout ??= TimeSpan.FromSeconds(5);

        byte[] ntpData = BuildNtpRequest();

        using var udpClient = new UdpClient();
        udpClient.Client.ReceiveTimeout = (int)timeout.Value.TotalMilliseconds;
        udpClient.Client.SendTimeout    = (int)timeout.Value.TotalMilliseconds;

        try
        {
            await udpClient.SendAsync(ntpData, ntpData.Length, server, NtpPort)
                .WaitAsync(timeout.Value, cancellationToken);

            UdpReceiveResult result = await udpClient.ReceiveAsync(cancellationToken)
                .AsTask().WaitAsync(timeout.Value, cancellationToken);

            return ParseNtpResponse(result.Buffer);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"NTP query to '{server}' failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Tries multiple NTP servers in order, returning the first successful result.
    /// </summary>
    public static async Task<DateTimeOffset> GetNtpTimeWithFallbackAsync(
        string[]? servers = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        servers ??= DefaultNtpServers;
        List<Exception> errors = [];

        foreach (string server in servers)
        {
            try
            {
                return await GetNtpTimeAsync(server, timeout, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add(ex);
            }
        }

        throw new AggregateException(
            $"All NTP servers failed ({servers.Length} tried).", errors);
    }

    // ── Drift Measurement ─────────────────────────────────────────────────────

    /// <summary>
    /// Measures the difference between the system clock and an NTP server.
    /// </summary>
    /// <returns>
    /// Positive: system clock is behind NTP (NTP is ahead).
    /// Negative: system clock is ahead of NTP.
    /// </returns>
    public static async Task<ClockDriftResult> MeasureDriftAsync(
        string? server = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset before  = DateTimeOffset.UtcNow;
        DateTimeOffset ntpTime = await GetNtpTimeAsync(server, timeout, cancellationToken);
        DateTimeOffset after   = DateTimeOffset.UtcNow;

        DateTimeOffset localMid = before + (after - before) / 2;
        TimeSpan drift = ntpTime - localMid;

        return new ClockDriftResult(drift, ntpTime, localMid, server ?? DefaultNtpServers[0]);
    }

    // ── Corrected Time Provider ───────────────────────────────────────────────

    /// <summary>
    /// Creates an <see cref="ITimeProvider"/> that corrects for measured clock drift.
    /// </summary>
    public static async Task<ITimeProvider> CreateCorrectedTimeProviderAsync(
        string? server = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var drift = await MeasureDriftAsync(server, timeout, cancellationToken);
        return new OffsetTimeProvider(drift.Offset);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static byte[] BuildNtpRequest()
    {
        byte[] data = new byte[NtpPacketSize];
        // LI=0, Version=3, Mode=3 (client)
        data[0] = 0x1B;
        return data;
    }

    private static DateTimeOffset ParseNtpResponse(byte[] buffer)
    {
        if (buffer.Length < NtpPacketSize)
            throw new InvalidOperationException("NTP response too short.");

        // Transmit Timestamp: bytes 40-43 (seconds), 44-47 (fraction)
        ulong intPart  = ((ulong)buffer[40] << 24)
                       | ((ulong)buffer[41] << 16)
                       | ((ulong)buffer[42] << 8)
                       |  (ulong)buffer[43];

        ulong fracPart = ((ulong)buffer[44] << 24)
                       | ((ulong)buffer[45] << 16)
                       | ((ulong)buffer[46] << 8)
                       |  (ulong)buffer[47];

        ulong milliseconds = (intPart * 1000) + (fracPart * 1000 / 0x100000000UL);

        // NTP epoch starts 1900; convert to Unix
        long unixMs = (long)milliseconds - ((long)NtpEpochOffset * 1000);
        return DateTimeOffset.FromUnixTimeMilliseconds(unixMs);
    }
}

/// <summary>
/// Result of a clock drift measurement against an NTP server.
/// </summary>
public sealed class ClockDriftResult
{
    internal ClockDriftResult(TimeSpan offset, DateTimeOffset ntpTime, DateTimeOffset localTime, string server)
    {
        Offset    = offset;
        NtpTime   = ntpTime;
        LocalTime = localTime;
        Server    = server;
    }

    /// <summary>
    /// Clock correction offset.
    /// Positive: local clock is behind (add this to local time to get NTP time).
    /// Negative: local clock is ahead.
    /// </summary>
    public TimeSpan Offset { get; }

    /// <summary>Absolute offset in seconds.</summary>
    public double OffsetSeconds => Math.Abs(Offset.TotalSeconds);

    /// <summary>Whether the drift exceeds the given threshold.</summary>
    public bool ExceedsThreshold(TimeSpan threshold) => Math.Abs(Offset.TotalSeconds) > threshold.TotalSeconds;

    /// <summary>Whether the drift would cause TOTP issues with a 30-second default step and ±1 window.</summary>
    public bool IsProblematic => OffsetSeconds > 30;

    /// <summary>The NTP time obtained.</summary>
    public DateTimeOffset NtpTime { get; }

    /// <summary>The local system time at measurement.</summary>
    public DateTimeOffset LocalTime { get; }

    /// <summary>The NTP server queried.</summary>
    public string Server { get; }

    /// <summary>Creates an <see cref="OffsetTimeProvider"/> correcting for this drift.</summary>
    public ITimeProvider CreateCorrectedTimeProvider()
        => new OffsetTimeProvider(Offset);

    /// <inheritdoc />
    public override string ToString()
        => $"Drift: {Offset.TotalMilliseconds:+0.###;-0.###;0}ms vs {Server} at {NtpTime:O}";
}
