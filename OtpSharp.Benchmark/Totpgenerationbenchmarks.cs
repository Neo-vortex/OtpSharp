using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharp.Algorithms; // Otp.NET (competitor)
using OtpSharp.Core;                       // Our library
using OtpSharp.Totp;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks TOTP code generation — the core hot path for any 2FA system.
/// Compares OtpSharp vs Otp.NET (kspearrin) under identical conditions.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class TotpGenerationBenchmarks
{
    // ── Shared state ──────────────────────────────────────────────────────────

    // RFC 4226/6238 standard test secret: ASCII "12345678901234567890"
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();
    private static readonly string SecretBase32 = OtpSharp.Core.Base32.Encode(SecretBytes, padOutput: false);

    // OtpSharp instances
    private OtpSecret           _ourSecret       = null!;
    private TotpGenerator       _ourTotp6        = null!;
    private TotpGenerator       _ourTotp8        = null!;
    private TotpGenerator       _ourTotpSha256   = null!;
    private TotpGenerator       _ourTotpSha512   = null!;

    // Otp.NET instances
    private OtpNet.Totp         _theirTotp6      = null!;
    private OtpNet.Totp         _theirTotp8      = null!;
    private OtpNet.Totp         _theirTotpSha256 = null!;
    private OtpNet.Totp         _theirTotpSha512 = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ourSecret       = new OtpSecret(SecretBytes);
        _ourTotp6        = new TotpGenerator(_ourSecret, TotpOptions.GoogleAuthenticator);
        _ourTotp8        = new TotpGenerator(_ourSecret, new TotpOptions { Digits = 8 });
        _ourTotpSha256   = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha256 });
        _ourTotpSha512   = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha512 });

        _theirTotp6        = new OtpNet.Totp(SecretBytes);
        _theirTotp8        = new OtpNet.Totp(SecretBytes, totpSize: 8);
        _theirTotpSha256   = new OtpNet.Totp(SecretBytes, mode: OtpHashMode.Sha256);
        _theirTotpSha512   = new OtpNet.Totp(SecretBytes, mode: OtpHashMode.Sha512);
    }

    [GlobalCleanup]
    public void Cleanup() => _ourSecret.Dispose();

    // ── 6-digit SHA1 (default / most common) ─────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Generate_6digit_SHA1")]
    public string TheirTotp6() => _theirTotp6.ComputeTotp();

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("TOTP_Generate_6digit_SHA1")]
    public string OurTotp6() => _ourTotp6.Generate().Code;

    // ── 8-digit SHA1 ─────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Generate_8digit_SHA1")]
    public string TheirTotp8() => _theirTotp8.ComputeTotp();

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("TOTP_Generate_8digit_SHA1")]
    public string OurTotp8() => _ourTotp8.Generate().Code;

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Generate_SHA256")]
    public string TheirTotpSha256() => _theirTotpSha256.ComputeTotp();

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("TOTP_Generate_SHA256")]
    public string OurTotpSha256() => _ourTotpSha256.Generate().Code;

    // ── SHA-512 ───────────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("TOTP_Generate_SHA512")]
    public string TheirTotpSha512() => _theirTotpSha512.ComputeTotp();

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("TOTP_Generate_SHA512")]
    public string OurTotpSha512() => _ourTotpSha512.Generate().Code;
}
