using OtpSharp.Algorithms;
using OtpSharp.Core;

namespace OtpSharp.Hotp;

/// <summary>
/// RFC 4226 HOTP (HMAC-based One-Time Password) generator and validator.
/// </summary>
/// <remarks>
/// <para>
/// HOTP uses an event counter rather than time. The counter must be synchronised
/// between the server and the authenticator device.
/// </para>
/// <para>
/// Thread-safety: This class is stateless (no internal counter); counter state is
/// managed externally via <see cref="IHotpCounterStore"/>. All methods are thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// var store  = new InMemoryHotpCounterStore();
/// var secret = OtpSecret.FromBase32("JBSWY3DPEHPK3PXP");
/// var hotp   = new HotpGenerator(secret);
///
/// // Generate at counter 0
/// OtpCode code = hotp.GenerateAt(0);
/// Console.WriteLine(code.Code);
///
/// // Validate (auto-advances counter in store)
/// var result = await hotp.ValidateAsync("user1", userInput, store);
/// </code>
/// </example>
public sealed class HotpGenerator
{
    private readonly OtpSecret  _secret;
    private readonly HotpOptions _options;

    // ── Construction ──────────────────────────────────────────────────────────

    /// <summary>Creates an HOTP generator with default RFC 4226 options.</summary>
    public HotpGenerator(OtpSecret secret)
        : this(secret, HotpOptions.Default) { }

    /// <summary>Creates an HOTP generator with the specified options.</summary>
    public HotpGenerator(OtpSecret secret, HotpOptions options)
    {
        _secret  = secret  ?? throw new ArgumentNullException(nameof(secret));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _options.Validate();
    }

    /// <summary>The active HOTP configuration.</summary>
    public HotpOptions Options => _options;

    // ── Generation ────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates the HOTP code for the given counter value.
    /// </summary>
    public OtpCode GenerateAt(long counter)
    {
        string code = ComputeCode(counter);
        return new OtpCode(code, counter, DateTimeOffset.UtcNow, null, null);
    }

    /// <summary>
    /// Generates HOTP codes for a range of counters.
    /// </summary>
    public IReadOnlyList<OtpCode> GenerateRange(long startCounter, int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        var results = new List<OtpCode>(count);
        for (long i = 0; i < count; i++)
            results.Add(GenerateAt(startCounter + i));
        return results;
    }

    // ── Validation (stateless) ────────────────────────────────────────────────

    /// <summary>
    /// Validates a code against a specific counter value (stateless — no store update).
    /// </summary>
    public OtpValidationResult ValidateAt(string userCode, long counter)
    {
        if (string.IsNullOrWhiteSpace(userCode))
            return OtpValidationResult.Failure("Code must not be empty.");

        string normalised = userCode.Trim();
        if (normalised.Length != _options.Digits)
            return OtpValidationResult.Failure(
                $"Expected {_options.Digits} digits, got {normalised.Length}.");

        string expected = ComputeCode(counter);
        bool match = DynamicTruncation.ConstantTimeEquals(expected, normalised);

        return match
            ? OtpValidationResult.Success(counter, 0, expected)
            : OtpValidationResult.Failure($"Code did not match counter {counter}.");
    }

    // ── Validation (stateful, with store) ─────────────────────────────────────

    /// <summary>
    /// Validates a user-supplied HOTP code using the counter from the store.
    /// On success, the store counter is advanced past the matched value.
    /// </summary>
    /// <param name="userCode">The code entered by the user.</param>
    /// <param name="keyId">Unique identifier for the user/device.</param>
    /// <param name="store">The counter store.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async ValueTask<OtpValidationResult> ValidateAsync(
        string userCode,
        string keyId,
        IHotpCounterStore store,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        ArgumentNullException.ThrowIfNull(store);

        if (string.IsNullOrWhiteSpace(userCode))
            return OtpValidationResult.Failure("Code must not be empty.");

        string normalised = userCode.Trim();
        if (normalised.Length != _options.Digits)
            return OtpValidationResult.Failure(
                $"Expected {_options.Digits} digits, got {normalised.Length}.");

        long currentCounter = await store.GetCounterAsync(keyId, cancellationToken);

        // Search the look-ahead window for a match
        for (int offset = 0; offset <= _options.LookAheadWindow; offset++)
        {
            long candidate = currentCounter + offset;
            string expected = ComputeCode(candidate);

            if (DynamicTruncation.ConstantTimeEquals(expected, normalised))
            {
                // Advance counter past the matched value
                await store.SetCounterAsync(keyId, candidate + 1, cancellationToken);
                return OtpValidationResult.Success(candidate, offset, expected);
            }
        }

        return OtpValidationResult.Failure(
            $"Code did not match any counter in [{currentCounter}, {currentCounter + _options.LookAheadWindow}].");
    }

    // ── Core computation ──────────────────────────────────────────────────────

    private string ComputeCode(long counter)
    {
        byte[] key = _secret.ToByteArray();
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
