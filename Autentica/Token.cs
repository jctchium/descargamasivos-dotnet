using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;

namespace Autentica
{
    class Token
    {
        private static String ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
        //private static String ENDPOINT = "https://srvsolicituddescargamasteruat.cloudapp.net/Autenticacion/Autenticacion.svc";
        private static String ACTION = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica";

        X509Certificate2 cert;
        public Token(String rutaPfx, String pass)
        {
            cert = new X509Certificate2(rutaPfx, pass);
        }

        public String Autenticar()
        {
            try
            {
                DateTime fechaI = DateTime.UtcNow;
                String timeStamp = ObtenerTimeStamp(fechaI);
                Console.WriteLine("Timestamp: " + timeStamp);
                var digest = CreaDigestValue(System.Text.Encoding.UTF8.GetBytes(timeStamp));
                Console.WriteLine("Digest: " + digest);
                var signInfo = ObtenerSignedInfo(digest);
                String signatureValue = Firma.Firmar(System.Text.Encoding.UTF8.GetBytes(signInfo), cert);
                Console.WriteLine("SignatureValue: " + signatureValue);
                var certString = Convert.ToBase64String(cert.GetRawCertData());
                //String soap = ObtenerSoap(fechaI.ToString("yyyy-MM-dd'T'HH:mm:ss"), fechaI.AddMinutes(5).ToString("yyyy-MM-dd'T'HH:mm:ss"));String soap = ObtenerSoap(fechaI.ToString("yyyy-MM-dd'T'HH:mm:ss"), fechaI.AddMinutes(5).ToString("yyyy-MM-dd'T'HH:mm:ss"));
                String soap = ObtenerSoap(timeStamp, certString, signInfo, signatureValue);
                Console.WriteLine("Soap: " + soap);
                var resp = Solicitud.SendRequest(soap, ENDPOINT, ACTION, "");
                return resp.Token;
            }
            catch (Exception)
            {

            }
            return "";
        }

        private static String ObtenerTimeStamp(DateTime fechaI){
            DateTime fechaF = fechaI.AddMinutes(5);

            //String timeStamp = "<u:Timestamp u:Id=\"_0\"><u:Created>" + fechaI.ToString("yyyy-MM-dd'T'HH:mm:ss") + ".000Z</u:Created><u:Expires>" + fechaF.ToString("yyyy-MM-dd'T'HH:mm:ss") + ".000Z</u:Expires></u:Timestamp>";
            //String timeStamp = "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\"><u:Created>" + fechaI.ToString("yyyy-MM-dd'T'HH:mm:ss") + ".000Z</u:Created><u:Expires>" + fechaF.ToString("yyyy-MM-dd'T'HH:mm:ss") + ".000Z</u:Expires></u:Timestamp>";
            String timeStamp = "<u:Timestamp u:Id=\"_0\"><u:Created>" + fechaI.ToString("yyyy-MM-dd'T'HH:mm:ss") + "Z</u:Created><u:Expires>" + fechaF.ToString("yyyy-MM-dd'T'HH:mm:ss") + "Z</u:Expires></u:Timestamp>";
            return timeStamp;
            //return "<u:Timestamp xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" u:Id=\"_0\"><u:Created>2019-02-08T06:38:08.000Z</u:Created><u:Expires>2019-02-08T06:43:08.000Z</u:Expires></u:Timestamp>";
        }

        private static String CreaDigestValue(byte [] bytesTimeStamp){
            try{
                byte[] digestValueBytes = Org.BouncyCastle.Security.DigestUtilities.CalculateDigest("sha1", bytesTimeStamp);
                var digestValue = Convert.ToBase64String(digestValueBytes);
                return digestValue;
            }
            catch (Exception){
                return null;
            }
        }

        private static String ObtenerSignedInfo(String digest){
            //String signInfo = "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>" + digest + "</DigestValue></Reference></SignedInfo>";
            //String signInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>" + digest + "</DigestValue></Reference></SignedInfo>";
            String signInfo = "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>" + digest + "</DigestValue></Reference></SignedInfo>";

            return signInfo;
            //return "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></CanonicalizationMethod><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></Transform></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod><DigestValue>TkB6rHvN5ZQNM8QDbcaOA1Jj32o=</DigestValue></Reference></SignedInfo>";
        }

        private static String ObtenerSoap(String timeStamp, String certificado, String signInfo, String signedInfo){
            //String soap = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" + timeStamp + "<o:BinarySecurityToken u:Id=\"uuid-b246ed31-bfec-804a-5212-095ac6d97d3c-1\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + certificado + "</o:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" + signInfo + "<SignatureValue>" + signedInfo + "</SignatureValue><KeyInfo><o:SecurityTokenReference><o:Reference ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" URI=\"#uuid-b246ed31-bfec-804a-5212-095ac6d97d3c-1\"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header><s:Body><Autentica xmlns=\"http://DescargaMasivaTerceros.gob.mx\"/></s:Body></s:Envelope>";
            //String soap = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Header><o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" + timeStamp + "<o:BinarySecurityToken u:Id=\"uuid-b246ed31-bfec-804a-5212-095ac6d97d3c-1\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + certificado + "</o:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" + signInfo + "<SignatureValue>" + signedInfo + "</SignatureValue><KeyInfo><o:SecurityTokenReference><o:Reference ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" URI=\"#uuid-b246ed31-bfec-804a-5212-095ac6d97d3c-1\"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header><s:Body><Autentica xmlns=\"http://DescargaMasivaTerceros.gob.mx\"/></s:Body></s:Envelope>";
            String soap = "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">" + timeStamp + "<o:BinarySecurityToken u:Id=\"uuid-49569d72-988a-42bf-a566-7041adb65ddd\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">" + certificado + "</o:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" + signInfo + "<SignatureValue>" + signedInfo + "</SignatureValue><KeyInfo><o:SecurityTokenReference><o:Reference ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" URI=\"#uuid-49569d72-988a-42bf-a566-7041adb65ddd\"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header><s:Body><Autentica xmlns=\"http://DescargaMasivaTerceros.gob.mx\"/></s:Body></s:Envelope>";
            return soap;
        }
    }
}