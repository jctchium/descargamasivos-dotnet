using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Autentica
{
    class Firma
    {
        public static String Firmar(byte [] data, X509Certificate2 cert){
            String firmaDigitalBase64 = FirmarConPFX(data, cert);
            return firmaDigitalBase64;
        }

        private static String FirmarConPFX(byte [] data, X509Certificate2 cert){
            var _cert = Convert.ToBase64String(cert.GetRawCertData());
            var rsa = (RSACryptoServiceProvider)cert.PrivateKey;
            var signature = rsa.SignData(data, 0, data.Length, new SHA1CryptoServiceProvider());
            var s = Convert.ToBase64String(signature);
            return s;
        }
    }
}