using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharper.Core;
using OtpSharper.Totp;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks TOTP validation — the server-side hot path.
/// Includes strict (no window) and RFC-recommended (±1 step) window scenarios.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class TotpValidationBenchmarks
{
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();

    // OtpSharper
    private OtpSecret     _ourSecret   = null!;
    private TotpGenerator _ourStrict   = null!;   // window = 0
    private TotpGenerator _ourWindow1  = null!;   // window = ±1

    // Otp.NET
    private OtpNet.Totp   _theirTotp   = null!;
    private VerificationWindow _theirNoWindow   = null!;
    private VerificationWindow _theirWindow1    = null!;

    // Pre-computed valid code so generation cost isn't included
    private string _validCode = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ourSecret  = new OtpSecret(SecretBytes);
        _ourStrict  = new TotpGenerator(_ourSecret, new TotpOptions { ValidationWindowSteps = 0 });
        _ourWindow1 = new TotpGenerator(_ourSecret, new TotpOptions { ValidationWindowSteps = 1 });

        _theirTotp    = new OtpNet.Totp(SecretBytes);
        _theirNoWindow = new VerificationWindow(0, 0);
        _theirWindow1  = VerificationWindow.RfcSpecifiedNetworkDelay;

        _validCode = _ourStrict.Generate().Code;
    }

    [GlobalCleanup]
    public void Cleanup() => _ourSecret.Dispose();

    // ── Strict (current step only) ────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Validate_Strict")]
    public bool TheirValidateStrict()
        => _theirTotp.VerifyTotp(_validCode, out _, _theirNoWindow);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("TOTP_Validate_Strict")]
    public bool OurValidateStrict()
        => _ourStrict.Validate(_validCode).IsValid;

    // ── RFC window (±1 step) ──────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Validate_Window1")]
    public bool TheirValidateWindow1()
        => _theirTotp.VerifyTotp(_validCode, out _, _theirWindow1);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("TOTP_Validate_Window1")]
    public bool OurValidateWindow1()
        => _ourWindow1.Validate(_validCode).IsValid;

    // ── Failed validation (wrong code) ────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Validate_Failure")]
    public bool TheirValidateFailure()
        => _theirTotp.VerifyTotp("000000", out _, _theirWindow1);

    [Benchmark(Description = "OtpSharper")]
    [BenchmarkCategory("TOTP_Validate_Failure")]
    public bool OurValidateFailure()
        => _ourWindow1.Validate("000000").IsValid;
}
