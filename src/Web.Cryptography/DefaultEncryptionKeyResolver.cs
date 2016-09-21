// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Microsoft.Azure.Web.Cryptography
{
    public class DefaultEncryptionKeyResolver : IEncryptionKeyResolver
    {
        public const string DefaultEncryptionKeyId = "default";
        private const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";

        private static readonly string[] DefaultKeyIdMappings = new[] { DefaultEncryptionKeyId, Constants.AzureWebsiteEncryptionKey };
        private readonly string _rootWebConfigPath;
        private CryptographicKey _defaultKey;

        public DefaultEncryptionKeyResolver()
            : this(Constants.RootWebConfigPath)
        {

        }

        internal DefaultEncryptionKeyResolver(string configPath)
        {
            _rootWebConfigPath = configPath;
        }

        public CryptographicKey ResolveKey(string keyId) => string.IsNullOrEmpty(keyId) ? GetCurrentKey() : GetNamedKey(keyId);

        private CryptographicKey GetNamedKey(string keyId)
        {
            string keyValue = IsDefaultKey(keyId) ? GetDefaultKeyValue() : Environment.GetEnvironmentVariable(keyId);

            if (keyValue != null)
            {
                return CryptographicKey.FromHexString(keyId, keyValue);
            }

            return null;
        }

        private CryptographicKey GetCurrentKey()
        {
            string keyId = Environment.GetEnvironmentVariable(Constants.AzureWebsiteEncryptionKeyId);

            if (keyId != null)
            {
                return GetNamedKey(keyId);
            }

            return GetDefaultKey();
        }

        private CryptographicKey GetDefaultKey()
        {
            if (_defaultKey == null)
            {
                string keyValue = GetDefaultKeyValue();

                if (keyValue != null)
                {
                    _defaultKey = CryptographicKey.FromHexString(DefaultEncryptionKeyId, keyValue);
                }
            }

            return _defaultKey;
        }

        private string GetDefaultKeyValue()
        {
            if (IsAzureEnvironment())
            {
                // If running in Azure, try to pull the key from the environment
                // and fallback to config file if not available
                return Environment.GetEnvironmentVariable(Constants.AzureWebsiteEncryptionKey) ?? GetMachineConfigKey(_rootWebConfigPath);
            }

            return Environment.GetEnvironmentVariable(Constants.AzureWebsiteLocalEncryptionKey);
        }

        private static bool IsAzureEnvironment() => Environment.GetEnvironmentVariable(Constants.AzureWebsiteInstanceId) != null;

        private static bool IsDefaultKey(string keyName) => DefaultKeyIdMappings.Contains(keyName, StringComparer.OrdinalIgnoreCase);

        private static string GetMachineConfigKey(string configPath)
        {
            string key = null;
            if (File.Exists(configPath))
            {
                using (var reader = new StringReader(File.ReadAllText(configPath)))
                {
                    var xdoc = XDocument.Load(reader);

                    string siteName = Environment.GetEnvironmentVariable(Constants.AzureWebsiteName);
                    string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

                    key = ((IEnumerable)xdoc.XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
                }
            }

            return key;
        }
    }
}
