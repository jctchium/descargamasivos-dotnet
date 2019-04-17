using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;

namespace Autentica
{
    class Solicitud
    {
        public static Respuesta SendRequest(String postData, String url, String soapAction, String token)
        {
            var resp = new Respuesta();
            try { 
                System.Net.ServicePointManager.CertificatePolicy = new TrustAllCertificatePolicy();
                WebRequest request = WebRequest.Create(url);
                request.Method = "POST";
                byte[] byteArray = Encoding.UTF8.GetBytes(postData);
                request.ContentType = "text/xml; charset=utf-8";
                request.Headers.Add("SOAPAction: \"" + soapAction + "\"");
                if (!String.IsNullOrEmpty(token)){
                    request.Headers.Add("Authorization", String.Format("WRAP access_token=\"{0}\"", token));
                }
                request.ContentLength = byteArray.Length;
                Stream dataStream = request.GetRequestStream();                
                dataStream.Write(byteArray, 0, byteArray.Length);
                Console.WriteLine("Length: " + byteArray.Length);
                dataStream.Close();
                WebResponse response = request.GetResponse();

                dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                String responseFromServer = reader.ReadToEnd();
                System.Xml.XmlDocument xmlDoc = new System.Xml.XmlDocument();
                xmlDoc.LoadXml(responseFromServer);
                if(xmlDoc.GetElementsByTagName("AutenticateResult").Count > 0){
                    resp.Token = xmlDoc.GetElementsByTagName("AutenticateResult")[0].InnerText;
                }
                reader.Close();
                dataStream.Close();
                return resp;
            }
            catch (Exception ex)
            {
                String message = ex.Message;
                resp.CodeStatus = 0;
            }

            return resp;
        }
    }
}