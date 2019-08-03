// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class DataProtectorBuilderExtensions
    {
        public static IDataProtectionBuilder UseAzureWebsitesProviderSettings(this IDataProtectionBuilder builder, bool skipEnvironmentValidation = false)
        {
            if (skipEnvironmentValidation || Util.IsAzureEnvironment() || Util.IsLinuxContainerEnvironment())
            {
                builder.DisableAutomaticKeyGeneration();
                builder.SetDefaultKeyLifetime(TimeSpan.MaxValue);
                builder.Services.Configure<KeyManagementOptions>(options 
                    => options.XmlRepository = new AzureWebsitesXmlRepository(options.AuthenticatedEncryptorConfiguration));
            }

            return builder;
        }
    }
}
