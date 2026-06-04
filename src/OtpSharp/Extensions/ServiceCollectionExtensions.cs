using Microsoft.Extensions.DependencyInjection;
using OtpSharp.Abstractions;
using OtpSharp.Core;
using OtpSharp.Totp;

namespace OtpSharp.Extensions;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> DI registration.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="TotpGenerator"/> as a singleton with the provided secret and options.
    /// </summary>
    public static IServiceCollection AddTotp(
        this IServiceCollection services,
        string base32Secret,
        TotpOptions? options = null)
    {
        var secret = OtpSecret.FromBase32(base32Secret);
        var generator = new TotpGenerator(secret, options ?? TotpOptions.Default);
        services.AddSingleton(generator);
        return services;
    }

    /// <summary>
    /// Registers <see cref="TotpGenerator"/> using a builder action.
    /// </summary>
    public static IServiceCollection AddTotp(
        this IServiceCollection services,
        string base32Secret,
        Action<TotpOptionsBuilder> configure)
    {
        var secret = OtpSecret.FromBase32(base32Secret);
        var builder = new TotpOptionsBuilder();
        configure(builder);
        var generator = new TotpGenerator(secret, builder.Build());
        services.AddSingleton(generator);
        return services;
    }

    /// <summary>
    /// Registers <see cref="OtpManager"/> as a singleton.
    /// </summary>
    public static IServiceCollection AddOtpManager(
        this IServiceCollection services,
        string otpauthUri)
    {
        var manager = OtpManager.FromUri(otpauthUri);
        services.AddSingleton(manager);
        return services;
    }

    /// <summary>
    /// Registers <see cref="TotpValidationService"/> as a singleton with the provided options.
    /// </summary>
    public static IServiceCollection AddTotpValidationService(
        this IServiceCollection services,
        TotpOptions? options = null)
    {
        services.AddSingleton(new TotpValidationService(options));
        return services;
    }

    /// <summary>
    /// Registers <see cref="OtpBackoffPolicy"/> as a singleton with optional configuration.
    /// </summary>
    public static IServiceCollection AddOtpBackoffPolicy(
        this IServiceCollection services,
        OtpBackoffOptions? options = null)
    {
        services.AddSingleton(new OtpBackoffPolicy(options ?? new OtpBackoffOptions()));
        return services;
    }

    /// <summary>
    /// Registers <see cref="UsedCodeTracker"/> as a singleton for replay attack prevention.
    /// </summary>
    public static IServiceCollection AddOtpUsedCodeTracker(
        this IServiceCollection services,
        TimeSpan? maxAge = null)
    {
        services.AddSingleton(new UsedCodeTracker(maxAge));
        return services;
    }
}

/// <summary>
/// Convenience extension methods on <see cref="string"/> for OTP operations.
/// </summary>
public static class StringOtpExtensions
{
    /// <summary>
    /// Validates this string as a TOTP code against the given generator.
    /// </summary>
    public static bool IsValidTotp(this string code, TotpGenerator generator)
        => generator.Validate(code).IsValid;

    /// <summary>
    /// Parses this string as an <c>otpauth://</c> URI.
    /// </summary>
    public static OtpSharp.Uri.OtpUri ParseAsOtpUri(this string uri)
        => OtpSharp.Uri.OtpUri.Parse(uri);
}
