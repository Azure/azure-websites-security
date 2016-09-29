using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class DataProtectorBuilderExtensions
    {
        public static IDataProtectionBuilder UseAzureWebsitesProviderSettings(this IDataProtectionBuilder builder, bool skipEnvironmentValidation = false)
        {
            if (skipEnvironmentValidation || Util.IsAzureEnvironment())
            {
                builder.DisableAutomaticKeyGeneration();
                builder.SetDefaultKeyLifetime(TimeSpan.MaxValue);
                builder.Services.AddSingleton<IXmlRepository, AzureWebsitesXmlRepository>();
            }

            return builder;
        }
    }
}
