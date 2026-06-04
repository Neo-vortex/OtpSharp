using OtpSharper.Algorithms;
using OtpSharper.Core;

namespace OtpSharper.Totp;

/// <summary>
/// RFC 6238 TOTP (Time-based One-Time Password) generator and validator.
/// </summary>
/// <remarks>
/// <para>
/// This implementation is fully RFC 6238 compliant and extends it with:
/// <list type="bullet">
///   <item>Configurable HMAC algorithms (SHA1, SHA256, SHA384, SHA512, SHA3-256, SHA3-512)</item>
///   <item>Configurable digit count (1–10)</item>
///   <item>Custom epoch (T0)</item>
///   <item>Asymmetric validation windows (separate look-ahead / look-behind)</item>
///   <item>Constant-time code comparison (anti-timing-attack)</item>
///   <item>Rich result objects with matched-counter and window-offset metadata</item>
/// </list>
/// </para>
/// <para>
/// Thread-safety: This class is stateless and fully thread-safe for concurrent use.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
/// var totp = new TotpGenerator(secret);
///
/// OtpCode code = totp.Generate();
/// Console.WriteLine($"Code: {code.Code}, expires in {code.RemainingSeconds}s");
///
/// OtpValidationResult result = totp.Validate(userInput);
/// if (result.IsValid)
///     Console.WriteLine($"Accepted at window offset {result.WindowOffset}");
/// </code>
/// </example>
public sealed class TotpGenerator
{
    private readonly OtpSecret   _secret;
    private readonly TotpOptions _options;

    // ── Construction ──────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a TOTP generator with the given secret and default RFC 6238 options.
    /// </summary>
    public TotpGenerator(OtpSecret secret)
        : this(secret, TotpOptions.Default) { }

    /// <summary>
    /// Creates a TOTP generator with the given secret and options.
    /// </summary>
    public TotpGenerator(OtpSecret secret, TotpOptions options)
    {
        _secret  = secret  ?? throw new ArgumentNullException(nameof(secret));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
    }

    /// <summary>
    /// Creates a TOTP generator using a fluent builder to configure options.
    /// </summary>
    public TotpGenerator(OtpSecret secret, Action<TotpOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new TotpOptionsBuilder();
        configure(builder);
        _secret  = secret;
        _options = builder.Build();
    }

    // ── Properties ────────────────────────────────────────────────────────────

    /// <summary>The active TOTP configuration.</summary>
    public TotpOptions Options => _options;

    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates the current TOTP code for the current time.
    /// </summary>
    public OtpCode Generate()
        => GenerateAt(_options.TimeProvider.UtcNow);

    /// <summary>
    /// Generates the TOTP code for a specific point in time.
    /// </summary>
    public OtpCode GenerateAt(DateTimeOffset timestamp)
    {
        long counter = UnixTime.GetCounter(timestamp, _options.StepSeconds, _options.Epoch);
        string code  = ComputeCode(counter);

        int remaining = UnixTime.RemainingSeconds(timestamp, _options.StepSeconds, _options.Epoch);
        DateTimeOffset expiry = timestamp.AddSeconds(remaining);

        return new OtpCode(code, counter, timestamp, remaining, expiry);
    }

    /// <summary>
    /// Generates the TOTP code for a specific counter (time step) value.
    /// </summary>
    public OtpCode GenerateForCounter(long counter)
    {
        string code = ComputeCode(counter);
        return new OtpCode(code, counter, _options.TimeProvider.UtcNow, null, null);
    }

    /// <summary>
    /// Generates codes for all time steps within the current validation window.
    /// Useful for debugging drift issues.
    /// </summary>
    public IReadOnlyList<(int Offset, OtpCode Code)> GenerateWindow()
    {
        DateTimeOffset now     = _options.TimeProvider.UtcNow;
        long currentCounter    = UnixTime.GetCounter(now, _options.StepSeconds, _options.Epoch);
        int behind             = _options.TotalLookBehind;
        int ahead              = _options.TotalLookAhead;

        var results = new List<(int, OtpCode)>(behind + ahead + 1);

        for (int offset = -behind; offset <= ahead; offset++)
        {
            long counter = currentCounter + offset;
            string code  = ComputeCode(counter);
            // compute approximate timestamp for this step
            DateTimeOffset stepTime = _options.Epoch.AddSeconds(counter * _options.StepSeconds);
            var otpCode = new OtpCode(code, counter, stepTime, null, null);
            results.Add((offset, otpCode));
        }

        return results;
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Validates a user-supplied OTP code against the current time and window.
    /// </summary>
    /// <param name="userCode">The code entered by the user.</param>
    /// <returns>A <see cref="OtpValidationResult"/> indicating success or failure.</returns>
    public OtpValidationResult Validate(string userCode)
        => ValidateAt(userCode, _options.TimeProvider.UtcNow);

    /// <summary>
    /// Validates a user-supplied OTP code against a specific timestamp.
    /// </summary>
    /// <param name="userCode">The code entered by the user.</param>
    /// <param name="timestamp">The reference timestamp for validation.</param>
    public OtpValidationResult ValidateAt(string userCode, DateTimeOffset timestamp)
    {
        if (string.IsNullOrWhiteSpace(userCode))
            return OtpValidationResult.Failure("Code must not be empty.");

        string normalised = userCode.Trim();

        if (normalised.Length != _options.Digits)
            return OtpValidationResult.Failure(
                $"Expected {_options.Digits} digits, got {normalised.Length}.");

        long currentCounter = UnixTime.GetCounter(timestamp, _options.StepSeconds, _options.Epoch);
        int  behind         = _options.TotalLookBehind;
        int  ahead          = _options.TotalLookAhead;

        for (int offset = -behind; offset <= ahead; offset++)
        {
            long candidate = currentCounter + offset;
            string expected = ComputeCode(candidate);

            bool match = _options.UseConstantTimeComparison
                ? DynamicTruncation.ConstantTimeEquals(expected, normalised)
                : expected == normalised;

            if (match)
                return OtpValidationResult.Success(candidate, offset, expected);
        }

        return OtpValidationResult.Failure(
            $"Code did not match any step in window [{-behind}, +{ahead}].");
    }

    // ── Time helpers ──────────────────────────────────────────────────────────

    /// <summary>Returns seconds remaining in the current time step window.</summary>
    public int RemainingSeconds()
        => UnixTime.RemainingSeconds(_options.TimeProvider.UtcNow, _options.StepSeconds, _options.Epoch);

    /// <summary>Returns when the current code expires.</summary>
    public DateTimeOffset CurrentExpiry()
        => UnixTime.StepExpiry(_options.TimeProvider.UtcNow, _options.StepSeconds, _options.Epoch);

    /// <summary>Returns the current counter (time step) value.</summary>
    public long CurrentCounter()
        => UnixTime.GetCounter(_options.TimeProvider.UtcNow, _options.StepSeconds, _options.Epoch);

    // ── Core computation ──────────────────────────────────────────────────────

    private string ComputeCode(long counter)
    {
        byte[] key  = _secret.ToByteArray();
        try
        {
            byte[] hash = HmacProvider.ComputeHash(_options.Algorithm, key, counter);
            uint   code = DynamicTruncation.Extract(hash, _options.Digits);
            return DynamicTruncation.Format(code, _options.Digits);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        }
    }
}
