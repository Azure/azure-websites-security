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
        public static IDataProtectionProvider CreateAzureDataProtector()
        {
            var serviceCollection = new ServiceCollection();
            var builder = serviceCollection.AddDataProtection()
                .UseAzureWebsitesProviderSettings();

            return serviceCollection.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>();
        }
    }
}
