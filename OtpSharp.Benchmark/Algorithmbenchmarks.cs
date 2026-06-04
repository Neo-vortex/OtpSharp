using BenchmarkDotNet.Attributes;
using OtpNet;
using OtpSharp.Algorithms;
using OtpSharp.Core;
using OtpSharp.Totp;

namespace OtpSharp.Benchmarks;

/// <summary>
/// Benchmarks TOTP generation across all supported hash algorithms.
/// Highlights OtpSharp's exclusive SHA3 support and compares shared algorithms.
/// </summary>
[MemoryDiagnoser]
[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
public class AlgorithmBenchmarks
{
    // Use a 64-byte secret that works for all algorithms
    private static readonly byte[] SecretBytes64 = new byte[64];

    static AlgorithmBenchmarks()
    {
        for (int i = 0; i < 64; i++) SecretBytes64[i] = (byte)(i + 1);
    }

    // OtpSharp
    private OtpSecret     _ourSecret  = null!;
    private TotpGenerator _ourSha1    = null!;
    private TotpGenerator _ourSha256  = null!;
    private TotpGenerator _ourSha384  = null!;
    private TotpGenerator _ourSha512  = null!;
    private TotpGenerator _ourSha3_256 = null!;
    private TotpGenerator _ourSha3_512 = null!;

    // Otp.NET
    private OtpNet.Totp _theirSha1   = null!;
    private OtpNet.Totp _theirSha256 = null!;
    private OtpNet.Totp _theirSha512 = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ourSecret   = new OtpSecret(SecretBytes64);
        _ourSha1     = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha1    });
        _ourSha256   = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha256  });
        _ourSha384   = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha384  });
        _ourSha512   = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha512  });
        _ourSha3_256 = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha3_256 });
        _ourSha3_512 = new TotpGenerator(_ourSecret, new TotpOptions { Algorithm = OtpAlgorithm.HmacSha3_512 });

        _theirSha1   = new OtpNet.Totp(SecretBytes64);
        _theirSha256 = new OtpNet.Totp(SecretBytes64, mode: OtpHashMode.Sha256);
        _theirSha512 = new OtpNet.Totp(SecretBytes64, mode: OtpHashMode.Sha512);
    }

    [GlobalCleanup]
    public void Cleanup() => _ourSecret.Dispose();

    // ── SHA1 ──────────────────────────────────────────────────────────────────

    [Benchmark(Baseline = true, Description = "Otp.NET / SHA1")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string TheirSha1() => _theirSha1.ComputeTotp();

    [Benchmark(Description = "OtpSharp / SHA1")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha1() => _ourSha1.Generate().Code;

    // ── SHA256 ────────────────────────────────────────────────────────────────

    [Benchmark(Description = "Otp.NET / SHA256")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string TheirSha256() => _theirSha256.ComputeTotp();

    [Benchmark(Description = "OtpSharp / SHA256")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha256() => _ourSha256.Generate().Code;

    // ── SHA384 (OtpSharp exclusive) ───────────────────────────────────────────

    [Benchmark(Description = "OtpSharp / SHA384 (exclusive)")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha384() => _ourSha384.Generate().Code;

    // ── SHA512 ────────────────────────────────────────────────────────────────

    [Benchmark(Description = "Otp.NET / SHA512")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string TheirSha512() => _theirSha512.ComputeTotp();

    [Benchmark(Description = "OtpSharp / SHA512")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha512() => _ourSha512.Generate().Code;

    // ── SHA3-256 (OtpSharp exclusive) ─────────────────────────────────────────

    [Benchmark(Description = "OtpSharp / SHA3-256 (exclusive)")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha3_256() => _ourSha3_256.Generate().Code;

    // ── SHA3-512 (OtpSharp exclusive) ─────────────────────────────────────────

    [Benchmark(Description = "OtpSharp / SHA3-512 (exclusive)")]
    [BenchmarkCategory("Algorithm_Comparison")]
    public string OurSha3_512() => _ourSha3_512.Generate().Code;
}
