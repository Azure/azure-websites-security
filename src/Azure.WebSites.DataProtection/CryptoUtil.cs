﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.Azure.Web.DataProtection
{
    public static class CryptoUtil
    {
        public static byte[] ConvertHexToByteArray(string keyValue) 
            => Enumerable.Range(0, keyValue.Length / 2)
            .Select(b => Convert.ToByte(keyValue.Substring(b * 2, 2), 16))
            .ToArray();

        internal static byte[] CreateKey()
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.GenerateKey();
                return aes.Key;
            }
        }
    }
}
