using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.Azure.Web.DataProtection;
using Microsoft.Azure.Web.DataProtection.Tests;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Azure.WebSites.DataProtection.UnitTests
{
    public class DataProtectorBuilderExtensionsTests
    {
        [Theory]
        [InlineData(true, "", "", true)]
        [InlineData(true, "", "Name", true)]
        [InlineData(true, "Instance", "", true)]
        [InlineData(true, "Instance", "Name", true)]
        [InlineData(false, "", "", false)]
        [InlineData(false, "Instance", "", true)]
        [InlineData(false, "", "Name", true)]
        [InlineData(false, "Instance", "Name", true)]
        public void Enables_Data_Protection_Services_Based_On_Environment(bool skipEnvironment,
            string azureWebsiteInstanceId, string containerName, bool enablesDataProtection)
        {
            var environment = new Dictionary<string, string>
            {
                [Constants.AzureWebsiteInstanceId] = azureWebsiteInstanceId,
                [Constants.ContainerName] = containerName
            };

            using (new TestScopedEnvironmentVariable(environment))
            {
                var builder = new DataProtectionBuilder(new ServiceCollection());
                Assert.Empty(builder.Services);
                var dataProtectionBuilder = builder.UseAzureWebsitesProviderSettings(skipEnvironment);
                Assert.Equal(enablesDataProtection, dataProtectionBuilder.Services.Any());
            }
        }
    }
}