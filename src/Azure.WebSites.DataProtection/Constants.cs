// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class Constants
    {
        public const string AzureWebsiteName = "WEBSITE_SITE_NAME";
        public const string AzureWebsiteInstanceId = "WEBSITE_INSTANCE_ID";
        public const string AzureWebsiteEncryptionKey = "WEBSITE_AUTH_ENCRYPTION_KEY";
        public const string AzureWebsiteLocalEncryptionKey = "AzureWebEncryptionKey";
        public const string AzureWebsiteEncryptionKeyId = "AzureWebDefaultEncryptionKeyId";
        internal const string RootWebConfigPath = @"D:\local\config\rootweb.config";
        internal const string DefaultEncryptionKeyId = "00000000-0000-0000-0000-000000000000";
    }
}
