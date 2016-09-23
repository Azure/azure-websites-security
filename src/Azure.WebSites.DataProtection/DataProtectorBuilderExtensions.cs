using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class DataProtectorBuilderExtensions
    {
        public static IDataProtectionBuilder UseAzureWebsitesProviderSettings(this IDataProtectionBuilder builder, bool validateEnvironment = true)
        {
            if (validateEnvironment && Util.IsAzureEnvironment())
            {
                builder.DisableAutomaticKeyGeneration();
                builder.SetDefaultKeyLifetime(TimeSpan.MaxValue);
                builder.Services.AddSingleton<IKeyManager, AzureWebsitesKeyManager>();
            }

            return builder;
        }

        public static IDataProtectionBuilder WithLocalDevelopmentKeyResolver(this IDataProtectionBuilder builder)
            => WithCustomEncryptionKeyResolver(builder, s => new LocalDevelopmentKeyResolver());

   
        public static IDataProtectionBuilder WithLocalDevelopmentKeyResolver(this IDataProtectionBuilder builder, string testKey)
            => WithCustomEncryptionKeyResolver(builder, s => new LocalDevelopmentKeyResolver(testKey));

        
        public static IDataProtectionBuilder WithLocalDevelopmentKeyResolver(this IDataProtectionBuilder builder, byte[] testKey)
            => WithCustomEncryptionKeyResolver(builder, s => new LocalDevelopmentKeyResolver(testKey));

        public static IDataProtectionBuilder WithCustomEncryptionKeyResolver(this IDataProtectionBuilder builder, Func<IServiceProvider, IEncryptionKeyResolver> resolverFactory)
        {
            builder.Services.AddSingleton(resolverFactory);

            return builder;
        }
    }
}
