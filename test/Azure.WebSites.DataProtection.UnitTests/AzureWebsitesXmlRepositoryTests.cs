using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Moq;
using Xunit;

namespace Microsoft.Azure.Web.DataProtection.Tests
{
    public class AzureWebsitesXmlRepositoryTests
    {
        [Fact]
        public void GetAllKeys_WithNoKeysSet_ReturnsDefaultKey()
        {
            var configuration = new AuthenticatedEncryptorConfiguration();
            var resolver = new AzureWebsitesXmlRepository(configuration);
            string keyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A248";

            using (var variables = new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, keyValue))
            {
                IReadOnlyCollection<XElement> keys = resolver.GetAllElements();
                
                Assert.Equal(1, keys.Count);

                string key = ((IEnumerable)keys.First().XPathEvaluate("descriptor/descriptor/masterKey/value"))
                    .Cast<XElement>()
                    .FirstOrDefault()
                    .Value;

                var id = ((IEnumerable)keys.First().XPathEvaluate("@id"))
                    .Cast<XAttribute>()
                    .FirstOrDefault()
                    .Value;
                
                Assert.Equal(Util.ConvertHexToByteArray(keyValue), System.Convert.FromBase64String(key));
                Assert.Equal(Constants.DefaultEncryptionKeyId, id);
            }
        }

        [Fact]
        public void GetAllKeys_WithEnvironmentKeyPresent_UsesEnvironmentKey()
        {
            var configuration = new AuthenticatedEncryptorConfiguration();
            var resolver = new AzureWebsitesXmlRepository(configuration);
            string keyValue = "0F75CA46E7EBDD39E4CA6B074D1F9A5972B849A55F91A249";

            using (new TestScopedEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey, null))
            using (new TestScopedEnvironmentVariable(Constants.AzureWebsiteInstanceId, "test"))
            using (new TestScopedEnvironmentVariable(Constants.AzureWebsiteEnvironmentMachineKey, keyValue))
            {
                IReadOnlyCollection<XElement> keys = resolver.GetAllElements();

                Assert.Equal(1, keys.Count);

                string key = ((IEnumerable)keys.First().XPathEvaluate("descriptor/descriptor/masterKey/value"))
                    .Cast<XElement>()
                    .FirstOrDefault()
                    .Value;

                var id = ((IEnumerable)keys.First().XPathEvaluate("@id"))
                    .Cast<XAttribute>()
                    .FirstOrDefault()
                    .Value;

                Assert.Equal(Util.ConvertHexToByteArray(keyValue), System.Convert.FromBase64String(key));
                Assert.Equal(Constants.DefaultEncryptionKeyId, id);
            }
        }
    }
}
