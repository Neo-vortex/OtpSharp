using System.Security.Cryptography;
using OtpSharp.Core;

namespace OtpSharp.Steam;

/// <summary>
/// Steam Guard Mobile Authenticator code generator.
/// </summary>
/// <remarks>
/// <para>
/// Steam Guard uses a custom TOTP variant with:
/// <list type="bullet">
///   <item>HMAC-SHA1</item>
///   <item>30-second time step</item>
///   <item>5 characters from a custom 26-character alphabet (instead of numeric digits)</item>
///   <item>A custom character encoding step instead of RFC 4226 truncation</item>
/// </list>
/// </para>
/// <para>
/// The secret in Steam is stored as a Base64 string. Use <see cref="OtpSecret.FromBase64"/> or
/// <see cref="OtpSecret.FromBase32"/> as appropriate for your secret format.
/// </para>
/// </remarks>
public sealed class SteamGuardGenerator
{
    /// <summary>Steam Guard custom alphabet (26 chars, case-sensitive).</summary>
    public const string SteamAlphabet = "23456789BCDFGHJKMNPQRTVWXY";

    /// <summary>Steam Guard code length (always 5).</summary>
    public const int CodeLength = 5;

    /// <summary>Steam Guard time step (always 30 seconds).</summary>
    public const int StepSeconds = 30;

    private readonly OtpSecret      _secret;
    private readonly ITimeProvider  _timeProvider;

    // ── Construction ──────────────────────────────────────────────────────────

    /// <summary>Creates a Steam Guard generator.</summary>
    /// <param name="secret">The shared secret.</param>
    /// <param name="timeProvider">Optional time provider (default: system clock).</param>
    public SteamGuardGenerator(OtpSecret secret, ITimeProvider? timeProvider = null)
    {
        _secret       = secret ?? throw new ArgumentNullException(nameof(secret));
        _timeProvider = timeProvider ?? SystemTimeProvider.Instance;
    }

    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>Generates the current Steam Guard code.</summary>
    public SteamGuardCode Generate()
        => GenerateAt(_timeProvider.UtcNow);

    /// <summary>Generates a Steam Guard code for a specific timestamp.</summary>
    public SteamGuardCode GenerateAt(DateTimeOffset timestamp)
    {
        long counter = UnixTime.GetCounter(timestamp, StepSeconds);
        string code  = ComputeCode(counter);
        int remaining = UnixTime.RemainingSeconds(timestamp, StepSeconds);
        return new SteamGuardCode(code, counter, timestamp, remaining);
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates a user-supplied Steam Guard code with ±1 step tolerance.
    /// </summary>
    public OtpValidationResult Validate(string userCode, int windowSteps = 1)
        => ValidateAt(userCode, _timeProvider.UtcNow, windowSteps);

    /// <summary>
    /// Validates a Steam Guard code against a specific timestamp.
    /// </summary>
    public OtpValidationResult ValidateAt(string userCode, DateTimeOffset timestamp, int windowSteps = 1)
    {
        if (string.IsNullOrWhiteSpace(userCode))
            return OtpValidationResult.Failure("Code must not be empty.");

        string upper = userCode.Trim().ToUpperInvariant();
        if (upper.Length != CodeLength)
            return OtpValidationResult.Failure($"Steam Guard codes are {CodeLength} characters.");

        long current = UnixTime.GetCounter(timestamp, StepSeconds);

        for (int offset = -windowSteps; offset <= windowSteps; offset++)
        {
            string expected = ComputeCode(current + offset);
            if (DynamicTruncation.ConstantTimeEquals(expected, upper))
                return OtpValidationResult.Success(current + offset, offset, expected);
        }

        return OtpValidationResult.Failure("Steam Guard code did not match.");
    }

    /// <summary>Remaining seconds in the current time step.</summary>
    public int RemainingSeconds()
        => UnixTime.RemainingSeconds(_timeProvider.UtcNow, StepSeconds);

    // ── Core computation ──────────────────────────────────────────────────────

    private string ComputeCode(long counter)
    {
        // Counter to 8 bytes big-endian
        Span<byte> counterBytes = stackalloc byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        byte[] key = _secret.ToByteArray();
        try
        {
            using var hmac = new HMACSHA1(key);
            byte[] hash = hmac.ComputeHash(counterBytes.ToArray());

            // Steam custom alphabet encoding (5 chars)
            // Uses a different extraction from RFC 4226
            int b = hash[19] & 0x0F;
            uint codeInt = ((uint)hash[b]     & 0x7F) << 24
                         | ((uint)hash[b + 1] & 0xFF) << 16
                         | ((uint)hash[b + 2] & 0xFF) <<  8
                         | ((uint)hash[b + 3] & 0xFF);

            Span<char> result = stackalloc char[CodeLength];
            for (int i = 0; i < CodeLength; i++)
            {
                result[i] = SteamAlphabet[(int)(codeInt % (uint)SteamAlphabet.Length)];
                codeInt /= (uint)SteamAlphabet.Length;
            }

            return new string(result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

/// <summary>
/// Represents a generated Steam Guard code with metadata.
/// </summary>
public sealed class SteamGuardCode
{
    internal SteamGuardCode(string code, long counter, DateTimeOffset generatedAt, int remainingSeconds)
    {
        Code             = code;
        Counter          = counter;
        GeneratedAt      = generatedAt;
        RemainingSeconds = remainingSeconds;
        ExpiresAt        = generatedAt.AddSeconds(remainingSeconds);
    }

    /// <summary>The 5-character Steam Guard code.</summary>
    public string Code { get; }

    /// <summary>The counter (time step) used.</summary>
    public long Counter { get; }

    /// <summary>When this code was generated.</summary>
    public DateTimeOffset GeneratedAt { get; }

    /// <summary>Seconds until this code expires.</summary>
    public int RemainingSeconds { get; }

    /// <summary>When this code expires.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Returns the code string.</summary>
    public override string ToString() => Code;

    /// <summary>Implicit conversion to string.</summary>
    public static implicit operator string(SteamGuardCode c) => c.Code;
}
