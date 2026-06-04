namespace OtpSharp.Core;

/// <summary>
/// Represents the result of an OTP validation operation.
/// </summary>
public sealed class OtpValidationResult
{
    // ── Factory ───────────────────────────────────────────────────────────────

    /// <summary>Creates a successful validation result.</summary>
    public static OtpValidationResult Success(long matchedCounter, int windowOffset, string matchedCode)
        => new(true, matchedCounter, windowOffset, matchedCode, null);

    /// <summary>Creates a failed validation result.</summary>
    public static OtpValidationResult Failure(string reason)
        => new(false, default, default, null, reason);

    // ── Constructor ───────────────────────────────────────────────────────────

    private OtpValidationResult(
        bool isValid,
        long matchedCounter,
        int windowOffset,
        string? matchedCode,
        string? failureReason)
    {
        IsValid        = isValid;
        MatchedCounter = matchedCounter;
        WindowOffset   = windowOffset;
        MatchedCode    = matchedCode;
        FailureReason  = failureReason;
    }

    // ── Properties ────────────────────────────────────────────────────────────

    /// <summary>Whether the provided OTP was valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// The counter value (TOTP: time step; HOTP: counter) that produced the match.
    /// Only meaningful when <see cref="IsValid"/> is <c>true</c>.
    /// </summary>
    public long MatchedCounter { get; }

    /// <summary>
    /// The window offset at which the match occurred.
    /// 0 = current window, -1 = one step behind, +1 = one step ahead, etc.
    /// Only meaningful when <see cref="IsValid"/> is <c>true</c>.
    /// </summary>
    public int WindowOffset { get; }

    /// <summary>The exact OTP code that matched. Null on failure.</summary>
    public string? MatchedCode { get; }

    /// <summary>Human-readable failure reason. Null on success.</summary>
    public string? FailureReason { get; }

    /// <summary>Implicit conversion to <see cref="bool"/>.</summary>
    public static implicit operator bool(OtpValidationResult result) => result.IsValid;

    /// <inheritdoc />
    public override string ToString()
        => IsValid
            ? $"Valid (counter={MatchedCounter}, offset={WindowOffset:+#;-#;0})"
            : $"Invalid: {FailureReason}";
}

/// <summary>
/// Represents a generated OTP code with metadata.
/// </summary>
public sealed class OtpCode
{
    internal OtpCode(string code, long counter, DateTimeOffset generatedAt,
        int? remainingSeconds, DateTimeOffset? expiresAt)
    {
        Code             = code;
        Counter          = counter;
        GeneratedAt      = generatedAt;
        RemainingSeconds = remainingSeconds;
        ExpiresAt        = expiresAt;
    }

    /// <summary>The OTP code string (zero-padded to the configured digit length).</summary>
    public string Code { get; }

    /// <summary>The counter value used to generate this code.</summary>
    public long Counter { get; }

    /// <summary>UTC time when this code was generated.</summary>
    public DateTimeOffset GeneratedAt { get; }

    /// <summary>Remaining seconds this code is valid (null for HOTP).</summary>
    public int? RemainingSeconds { get; }

    /// <summary>UTC time when this code expires (null for HOTP).</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Whether this code has already expired.</summary>
    public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow >= ExpiresAt;

    /// <summary>Returns the code string.</summary>
    public override string ToString() => Code;

    /// <summary>Implicit conversion to the code string.</summary>
    public static implicit operator string(OtpCode code) => code.Code;
}
