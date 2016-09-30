// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class DataProtectionProvider
    {
        public static IDataProtectionProvider CreateAzureDataProtector(Action<IDataProtectionBuilder> configurationHandler = null)
        {
            return CreateAzureDataProtector(configurationHandler, false);
        }

        public static IDataProtectionProvider CreateAzureDataProtector(Action<IDataProtectionBuilder> configurationHandler, bool skipEnvironmentValidation = false)
        {
            var serviceCollection = new ServiceCollection();
            var builder = serviceCollection.AddDataProtection()
                .UseAzureWebsitesProviderSettings(skipEnvironmentValidation);

            configurationHandler?.Invoke(builder);

            return serviceCollection.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
        }
    }
}
