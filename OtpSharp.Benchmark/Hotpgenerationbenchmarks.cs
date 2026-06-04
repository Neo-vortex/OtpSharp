using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharp.Algorithms;
using OtpSharp.Core;
using OtpSharp.Hotp;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks HOTP code generation across various counter values and algorithms.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class HotpGenerationBenchmarks
{
    private static readonly byte[] SecretBytes = "12345678901234567890"u8.ToArray();

    // OtpSharp
    private OtpSecret     _ourSecret  = null!;
    private HotpGenerator _ourHotp    = null!;
    private HotpGenerator _ourHotp256 = null!;

    // Otp.NET
    private OtpNet.Hotp _theirHotp    = null!;
    private OtpNet.Hotp _theirHotp256 = null!;

    // Counter params
    [Params(0L, 1_000L, 1_000_000L)]
    public long Counter;

    [GlobalSetup]
    public void Setup()
    {
        _ourSecret  = new OtpSecret(SecretBytes);
        _ourHotp    = new HotpGenerator(_ourSecret);
        _ourHotp256 = new HotpGenerator(_ourSecret, new HotpOptions { Algorithm = OtpAlgorithm.HmacSha256 });

        _theirHotp    = new OtpNet.Hotp(SecretBytes);
        _theirHotp256 = new OtpNet.Hotp(SecretBytes, mode: OtpHashMode.Sha256);
    }

    [GlobalCleanup]
    public void Cleanup() => _ourSecret.Dispose();

    // ── SHA1 (default) ────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("HOTP_Generate_SHA1")]
    public string TheirHotpSha1() => _theirHotp.ComputeHOTP(Counter);

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("HOTP_Generate_SHA1")]
    public string OurHotpSha1() => _ourHotp.GenerateAt(Counter).Code;

    // ── SHA-256 ───────────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET")]
    [BenchmarkCategory("HOTP_Generate_SHA256")]
    public string TheirHotpSha256() => _theirHotp256.ComputeHOTP(Counter);

    [Benchmark(Description = "OtpSharp")]
    [BenchmarkCategory("HOTP_Generate_SHA256")]
    public string OurHotpSha256() => _ourHotp256.GenerateAt(Counter).Code;
}
