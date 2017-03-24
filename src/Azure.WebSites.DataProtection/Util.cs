// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.XPath;
using static Microsoft.Azure.Web.DataProtection.Constants;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class Util
    {
        internal static Guid DefaultKeyId = Guid.Parse(DefaultEncryptionKeyId);

        public static byte[] ConvertHexToByteArray(string keyValue) 
            => Enumerable.Range(0, keyValue.Length / 2)
            .Select(b => Convert.ToByte(keyValue.Substring(b * 2, 2), 16))
            .ToArray();

        public static bool IsAzureEnvironment() => Environment.GetEnvironmentVariable(Constants.AzureWebsiteInstanceId) != null;

        internal static byte[] CreateKey()
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.GenerateKey();
                return aes.Key;
            }
        }

        internal static string GetDefaultKeyValue() => Environment.GetEnvironmentVariable(AzureWebsiteLocalEncryptionKey) ?? GetMachineConfigKey();

        internal static bool IsDefaultKey(Guid keyId) => DefaultKeyId == keyId;

        internal static string GetMachineConfigKey()
        {
            string key = null;
            string configPath = Environment.ExpandEnvironmentVariables(RootWebConfigPath);
            if (IsAzureEnvironment() && File.Exists(configPath))
            {
                using (var reader = new StringReader(File.ReadAllText(configPath)))
                {
                    var xdoc = XDocument.Load(reader);

                    string siteName = Environment.GetEnvironmentVariable(AzureWebsitesIISSiteName);
                    string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

                    key = ((IEnumerable)xdoc.XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
                }
            }

            return key;
        }
    }
}
