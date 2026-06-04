using OtpSharp.Algorithms;
using OtpSharp.Core;

namespace OtpSharp.Totp;

/// <summary>
/// Fluent builder for <see cref="TotpOptions"/>.
/// </summary>
/// <example>
/// <code>
/// var options = new TotpOptionsBuilder()
///     .WithAlgorithm(OtpAlgorithm.HmacSha256)
///     .WithStepSeconds(30)
///     .WithDigits(8)
///     .WithValidationWindow(1)
///     .Build();
/// </code>
/// </example>
public sealed class TotpOptionsBuilder
{
    private OtpAlgorithm    _algorithm            = TotpOptions.DefaultAlgorithm;
    private int             _stepSeconds          = TotpOptions.DefaultStepSeconds;
    private int             _digits               = TotpOptions.DefaultDigits;
    private DateTimeOffset  _epoch                = DateTimeOffset.UnixEpoch;
    private int             _windowSteps          = TotpOptions.DefaultWindowSteps;
    private int             _extraLookBehind      = 0;
    private int             _extraLookAhead       = 0;
    private ITimeProvider   _timeProvider         = SystemTimeProvider.Instance;
    private bool            _constantTimeCompare  = true;

    // ── Fluent setters ────────────────────────────────────────────────────────

    /// <summary>Sets the HMAC algorithm.</summary>
    public TotpOptionsBuilder WithAlgorithm(OtpAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>Sets the time step in seconds (default: 30).</summary>
    public TotpOptionsBuilder WithStepSeconds(int seconds)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(seconds, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(seconds, 3600);
        _stepSeconds = seconds;
        return this;
    }

    /// <summary>Sets the OTP digit length (default: 6).</summary>
    public TotpOptionsBuilder WithDigits(int digits)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(digits, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digits, 10);
        _digits = digits;
        return this;
    }

    /// <summary>Sets a custom epoch (T0 in RFC 6238). Default: Unix epoch.</summary>
    public TotpOptionsBuilder WithEpoch(DateTimeOffset epoch)
    {
        _epoch = epoch;
        return this;
    }

    /// <summary>
    /// Sets the symmetric validation window (before and after the current step).
    /// </summary>
    public TotpOptionsBuilder WithValidationWindow(int steps)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(steps);
        _windowSteps = steps;
        return this;
    }

    /// <summary>
    /// Adds extra look-behind steps on top of the symmetric window (for lagging clients).
    /// </summary>
    public TotpOptionsBuilder WithExtraLookBehind(int steps)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(steps);
        _extraLookBehind = steps;
        return this;
    }

    /// <summary>
    /// Adds extra look-ahead steps on top of the symmetric window (for fast-clock clients).
    /// </summary>
    public TotpOptionsBuilder WithExtraLookAhead(int steps)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(steps);
        _extraLookAhead = steps;
        return this;
    }

    /// <summary>Sets a custom time provider (e.g., NTP-adjusted or fixed for tests).</summary>
    public TotpOptionsBuilder WithTimeProvider(ITimeProvider provider)
    {
        _timeProvider = provider ?? throw new ArgumentNullException(nameof(provider));
        return this;
    }

    /// <summary>Uses a fixed clock offset for drift correction.</summary>
    public TotpOptionsBuilder WithClockOffset(TimeSpan offset)
    {
        _timeProvider = new OffsetTimeProvider(offset);
        return this;
    }

    /// <summary>
    /// Disables constant-time comparison (faster, but vulnerable to timing attacks).
    /// Only use in non-security-sensitive contexts.
    /// </summary>
    public TotpOptionsBuilder WithoutConstantTimeComparison()
    {
        _constantTimeCompare = false;
        return this;
    }

    // ── Preset shortcuts ──────────────────────────────────────────────────────

    /// <summary>Configures for Google Authenticator compatibility.</summary>
    public TotpOptionsBuilder AsGoogleAuthenticator()
    {
        _algorithm   = OtpAlgorithm.HmacSha1;
        _stepSeconds = 30;
        _digits      = 6;
        _windowSteps = 1;
        return this;
    }

    /// <summary>Configures for Microsoft Authenticator compatibility.</summary>
    public TotpOptionsBuilder AsMicrosoftAuthenticator()
    {
        _algorithm   = OtpAlgorithm.HmacSha1;
        _stepSeconds = 30;
        _digits      = 6;
        _windowSteps = 1;
        return this;
    }

    /// <summary>High security: SHA256, 8 digits, strict window.</summary>
    public TotpOptionsBuilder AsHighSecurity()
    {
        _algorithm   = OtpAlgorithm.HmacSha256;
        _stepSeconds = 30;
        _digits      = 8;
        _windowSteps = 0;
        return this;
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    /// <summary>Builds and validates the <see cref="TotpOptions"/>.</summary>
    public TotpOptions Build()
    {
        var options = new TotpOptions
        {
            Algorithm             = _algorithm,
            StepSeconds           = _stepSeconds,
            Digits                = _digits,
            Epoch                 = _epoch,
            ValidationWindowSteps = _windowSteps,
            ExtraLookBehindSteps  = _extraLookBehind,
            ExtraLookAheadSteps   = _extraLookAhead,
            TimeProvider          = _timeProvider,
            UseConstantTimeComparison = _constantTimeCompare,
        };
        options.Validate();
        return options;
    }
}
