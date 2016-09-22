using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class DataProtectorBuilderExtensions
    {
        public static IDataProtectionBuilder UseAzureWebsitesProviderSettings(this IDataProtectionBuilder builder)
        {
            builder.DisableAutomaticKeyGeneration();
            builder.Services.AddSingleton<IKeyManager, AzureWebsitesKeyManager>();

            return builder;
        }
    }
}
