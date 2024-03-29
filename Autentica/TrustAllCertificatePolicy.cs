﻿using System;
using System.Net;

namespace Autentica { 
    public class TrustAllCertificatePolicy : System.Net.ICertificatePolicy
    {
	    public TrustAllCertificatePolicy()
        { }

        public bool CheckValidationResult(ServicePoint sp,
                    System.Security.Cryptography.X509Certificates.X509Certificate cert,
                    WebRequest req,
                    int problem)
        {
            return true;
        }
    }
}