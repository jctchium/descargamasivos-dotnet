using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Autentica
{
    class Program
    {
        static void Main(string[] args)
        {
            /*String mensaje = "Hola Mundo";
            Console.WriteLine(mensaje);
            StreamWriter sw = new StreamWriter("C:\\DotNetFiles\\HelloWorld.txt");
            sw.WriteLine(mensaje);
            sw.Close();

            Console.ReadLine();*/

            //System.Net.ServicePointManager.CertificatePolicy = new TrustAllCertificatePolicy();
            //String rutaPfx = "C:\\Users\\jtemugin\\Downloads\\material-1549894787098\\material\\csd.pfx";
            //String pass = "12345678a";

            String rutaPfx = "C:\\Users\\jtemugin\\Downloads\\material-1549894787098\\material\\FIEL_Pruebas_MAG041126GT8.pfx";
            String pass = "password";
            //String rutaPfx = "C:\\Users\\jtemugin\\Downloads\\openssl-1.0.2j-fips-x86_64\\OpenSSL\\bin\\Claveprivada_FIEL_STO020301G28_20190205_181600.key.pfx";
            //String pass = "";

            X509Certificate2 cert = new X509Certificate2(rutaPfx, pass);
            Token tokenService = new Token(rutaPfx, pass);
            var tokenString = tokenService.Autenticar();
            Console.WriteLine("Token: " + tokenString);
            Console.ReadLine();
        }
    }
}
