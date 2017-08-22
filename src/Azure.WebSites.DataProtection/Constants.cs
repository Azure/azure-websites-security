// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class Constants
    {
        public const string AzureWebsitesIISSiteName = "WEBSITE_IIS_SITE_NAME";
        public const string AzureWebsiteInstanceId = "WEBSITE_INSTANCE_ID";
        public const string AzureWebsitePrimaryEncryptionKeyId = "AzureWebPrimaryEncryptionKey";
        public const string AzureWebsiteLocalEncryptionKey = "AzureWebEncryptionKey";
        public const string AzureWebsiteEnvironmentMachineKey = "MACHINEKEY_DecryptionKey";
        public const string AzureWebReferencedKeyPrefix = "AzureWebEncryptionKey_";
        public const string DefaultEncryptionKeyId = "00000000-0000-0000-0000-000000000000";
        internal const string RootWebConfigPath = @"%systemdrive%\local\config\rootweb.config";
        internal const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";
    }
}
