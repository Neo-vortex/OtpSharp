using OtpSharper.Algorithms;
using OtpSharper.Core;

namespace OtpSharper.Totp;

/// <summary>
/// Immutable configuration for a TOTP generator/validator.
/// Use <see cref="TotpOptionsBuilder"/> for a fluent construction API.
/// </summary>
public sealed class TotpOptions
{
    // ── Defaults (RFC 6238) ───────────────────────────────────────────────────

    /// <summary>RFC 6238 default: 30-second time step.</summary>
    public const int DefaultStepSeconds = 30;

    /// <summary>RFC 6238 default: 6 digits.</summary>
    public const int DefaultDigits = 6;

    /// <summary>RFC 6238 default: HMAC-SHA1.</summary>
    public const OtpAlgorithm DefaultAlgorithm = OtpAlgorithm.HmacSha1;

    /// <summary>Default validation window: ±1 step (1 step behind, current, 1 step ahead).</summary>
    public const int DefaultWindowSteps = 1;

    // ── Properties ────────────────────────────────────────────────────────────

    /// <summary>
    /// HMAC algorithm used for code generation.
    /// Default: <see cref="OtpAlgorithm.HmacSha1"/> (RFC 6238).
    /// </summary>
    public OtpAlgorithm Algorithm { get; init; } = DefaultAlgorithm;

    /// <summary>
    /// Time step in seconds. RFC 6238 recommends 30 or 60.
    /// Range: 1–3600.
    /// </summary>
    public int StepSeconds { get; init; } = DefaultStepSeconds;

    /// <summary>
    /// Number of OTP digits. RFC 4226/6238 specifies 6 or 8.
    /// Range: 1–10.
    /// </summary>
    public int Digits { get; init; } = DefaultDigits;

    /// <summary>
    /// Custom epoch. Default: Unix epoch (1970-01-01T00:00:00Z).
    /// RFC 6238 §4 allows a custom T0 epoch.
    /// </summary>
    public DateTimeOffset Epoch { get; init; } = DateTimeOffset.UnixEpoch;

    /// <summary>
    /// Number of time steps to allow before and after the current step during validation.
    /// A value of 1 means current ± 1 step (3 codes accepted). 0 = strict.
    /// Default: 1.
    /// </summary>
    public int ValidationWindowSteps { get; init; } = DefaultWindowSteps;

    /// <summary>
    /// Additional look-back window steps (older codes). Stacked on top of
    /// <see cref="ValidationWindowSteps"/>. Useful for very slow users.
    /// Default: 0.
    /// </summary>
    public int ExtraLookBehindSteps { get; init; } = 0;

    /// <summary>
    /// Additional look-ahead window steps (future codes). Stacked on top of
    /// <see cref="ValidationWindowSteps"/>. Useful for clients with fast-forward clocks.
    /// Default: 0.
    /// </summary>
    public int ExtraLookAheadSteps { get; init; } = 0;

    /// <summary>
    /// The time provider used to obtain the current UTC time.
    /// Default: <see cref="SystemTimeProvider.Instance"/>.
    /// </summary>
    public ITimeProvider TimeProvider { get; init; } = SystemTimeProvider.Instance;

    /// <summary>
    /// When <c>true</c>, validation uses constant-time comparison to prevent timing attacks.
    /// Default: <c>true</c>.
    /// </summary>
    public bool UseConstantTimeComparison { get; init; } = true;

    // ── Derived helpers ───────────────────────────────────────────────────────

    /// <summary>Total look-behind steps: window + extra.</summary>
    internal int TotalLookBehind => ValidationWindowSteps + ExtraLookBehindSteps;

    /// <summary>Total look-ahead steps: window + extra.</summary>
    internal int TotalLookAhead  => ValidationWindowSteps + ExtraLookAheadSteps;

    // ── Validation ────────────────────────────────────────────────────────────

    /// <summary>Validates option values and throws on invalid configuration.</summary>
    public void Validate()
    {
        if (StepSeconds is < 1 or > 3600)
            throw new InvalidOperationException($"{nameof(StepSeconds)} must be between 1 and 3600.");
        if (Digits is < 1 or > 10)
            throw new InvalidOperationException($"{nameof(Digits)} must be between 1 and 10.");
        if (ValidationWindowSteps < 0)
            throw new InvalidOperationException($"{nameof(ValidationWindowSteps)} must be ≥ 0.");
        if (ExtraLookBehindSteps < 0)
            throw new InvalidOperationException($"{nameof(ExtraLookBehindSteps)} must be ≥ 0.");
        if (ExtraLookAheadSteps < 0)
            throw new InvalidOperationException($"{nameof(ExtraLookAheadSteps)} must be ≥ 0.");
    }

    // ── Presets ───────────────────────────────────────────────────────────────

    /// <summary>RFC 6238 default: 30s step, 6 digits, SHA1, ±1 window.</summary>
    public static TotpOptions Default => new();

    /// <summary>Google Authenticator compatible: 30s, 6 digits, SHA1.</summary>
    public static TotpOptions GoogleAuthenticator => new()
    {
        Algorithm           = OtpAlgorithm.HmacSha1,
        StepSeconds         = 30,
        Digits              = 6,
        ValidationWindowSteps = 1,
    };

    /// <summary>High security: 30s, 8 digits, SHA256, strict window (0).</summary>
    public static TotpOptions HighSecurity => new()
    {
        Algorithm           = OtpAlgorithm.HmacSha256,
        StepSeconds         = 30,
        Digits              = 8,
        ValidationWindowSteps = 0,
    };

    /// <summary>
    /// Maximum security: 30s, 8 digits, SHA512, strict window.
    /// Note: incompatible with standard authenticator apps.
    /// </summary>
    public static TotpOptions MaxSecurity => new()
    {
        Algorithm           = OtpAlgorithm.HmacSha512,
        StepSeconds         = 30,
        Digits              = 8,
        ValidationWindowSteps = 0,
    };

    /// <summary>60-second step for slower users: 60s, 6 digits, SHA1, ±1 window.</summary>
    public static TotpOptions SixtySeconds => new()
    {
        Algorithm           = OtpAlgorithm.HmacSha1,
        StepSeconds         = 60,
        Digits              = 6,
        ValidationWindowSteps = 1,
    };
}
