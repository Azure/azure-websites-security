// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace Microsoft.Azure.Web.DataProtection
{
    public class DefaultEncryptionKeyResolver : IEncryptionKeyResolver
    {
        public const string DefaultEncryptionKeyId = "default";
        
        private static readonly string[] DefaultKeyIdMappings = new[] { DefaultEncryptionKeyId, Constants.AzureWebsiteEncryptionKey };

        public byte[] ResolveKey(string keyId) => string.IsNullOrEmpty(keyId) ? GetCurrentKey() : GetNamedKey(keyId);

        private byte[] GetNamedKey(string keyId)
        {
            string keyValue = IsDefaultKey(keyId) ? GetDefaultKeyValue() : Environment.GetEnvironmentVariable(keyId);

            if (keyValue != null)
            {
                return CryptoUtil.ConvertHexToByteArray(keyValue);
            }

            return null;
        }

        private byte[] GetCurrentKey()
        {
            string keyId = Environment.GetEnvironmentVariable(Constants.AzureWebsiteEncryptionKeyId);

            if (keyId != null)
            {
                return GetNamedKey(keyId);
            }

            return GetDefaultKey();
        }

        private byte[] GetDefaultKey()
        {
            
                string keyValue = GetDefaultKeyValue();

                if (keyValue != null)
                {
                 return   CryptoUtil.ConvertHexToByteArray(keyValue);
                }
            return null;
        }

        private string GetDefaultKeyValue()
        {
            if (IsAzureEnvironment())
            {
                // If running in Azure, try to pull the key from the environment
                // and fallback to config file if not available
                return Environment.GetEnvironmentVariable(Constants.AzureWebsiteEncryptionKey) ?? GetMachineConfigKey();
            }

            return Environment.GetEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey);
        }

        private static bool IsAzureEnvironment() => Environment.GetEnvironmentVariable(Constants.AzureWebsiteInstanceId) != null;

        private static bool IsDefaultKey(string keyName) => DefaultKeyIdMappings.Contains(keyName, StringComparer.OrdinalIgnoreCase);


        private static string GetMachineConfigKey()
        {
#if NET46
            return ((System.Web.Configuration.MachineKeySection)System.Configuration.ConfigurationManager.GetSection("system.web/machineKey")).DecryptionKey;
#elif NETSTANDARD1_3
            //const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";

            return string.Empty;
            //string key = null;
            //if (File.Exists(configPath))
            //{
            //    using (var reader = new StringReader(File.ReadAllText(configPath)))
            //    {
            //        var xdoc = XDocument.Load(reader);

            //        string siteName = Environment.GetEnvironmentVariable(Constants.AzureWebsiteName);
            //        string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

            //        key = ((IEnumerable)xdoc..XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
            //    }
            //}

            //return key;
#endif
        }

    }
}
