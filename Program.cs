using System;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Kernel.Pdf.Xobject;
using Org.BouncyCastle.Security;
namespace SignPdf
{
  public class X509Certificate2Signature : IExternalSignature
  {
    private String hashAlgorithm;
    private String encryptionAlgorithm;
    private X509Certificate2 certificate;

    public X509Certificate2Signature(X509Certificate2 certificate, String hashAlgorithm)
    {
      if (!certificate.HasPrivateKey)
        throw new ArgumentException("No private key.");
      this.certificate = certificate;
      this.hashAlgorithm = DigestAlgorithms.GetDigest(DigestAlgorithms.GetAllowedDigest(hashAlgorithm));
      if (certificate.PrivateKey is RSACryptoServiceProvider)
        encryptionAlgorithm = "RSA";
      else if (certificate.PrivateKey is DSACryptoServiceProvider)
        encryptionAlgorithm = "DSA";
      else
        throw new ArgumentException("Unknown encryption algorithm " + certificate.PrivateKey);
    }
    public virtual byte[] Sign(byte[] message)
    {
      if (certificate.PrivateKey is RSACryptoServiceProvider)
      {
        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)certificate.PrivateKey;
        return rsa.SignData(message, hashAlgorithm);
      }
      else
      {
        DSACryptoServiceProvider dsa = (DSACryptoServiceProvider)certificate.PrivateKey;
        return dsa.SignData(message);
      }
    }
    public virtual String GetHashAlgorithm()
    {
      return hashAlgorithm;
    }
    public virtual String GetEncryptionAlgorithm()
    {
      return encryptionAlgorithm;
    }
  }
  class Startup
  {
    public async Task<object> Invoke(dynamic input)
    {
      // Access Personal (MY) certificate store of current user
      X509Store myCertStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
      myCertStore.Open(OpenFlags.ReadOnly);
      // Find the certificate we'll use to sign
      X509Certificate2 certificate = null;
      foreach (X509Certificate2 cert in myCertStore.Certificates)
      {
        if (cert.GetSerialNumberString().Equals(input.serialNumber))
        {
          Console.WriteLine(cert.GetSerialNumberString());
          certificate = cert;
          break;
        }
      }
      PdfReader reader = new PdfReader(input.pdfSource);
      StampingProperties properties = new StampingProperties();
      properties.UseAppendMode();
      PdfSigner signer = new PdfSigner(reader, new FileStream(input.pdfDest, FileMode.Create), properties);
      signer.SetCertificationLevel(0);
      // Creating the appearance
      var pdfBox = signer.GetDocument().GetPage(input.page).GetMediaBox();
      input.rect.x = (float)input.rect.x;
      input.rect.y = (float)input.rect.y;
      input.rect.width = (float)input.rect.width * pdfBox.GetWidth();
      input.rect.height = (float)input.rect.height * pdfBox.GetHeight();
      PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
        .SetPageRect(new iText.Kernel.Geom.Rectangle(
          pdfBox.GetWidth() * input.rect.x, pdfBox.GetHeight() * (1 - input.rect.y) - input.rect.height,
          input.rect.width, input.rect.height
        ))
        .SetPageNumber(input.page)
        .SetLayer2Text(
          "Assinado de forma digital em " + System.DateTime.Now.ToString()
        )
        .SetLayer2FontSize(10)
        .SetRenderingMode(PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
      // Get Chain
      var chain = new Org.BouncyCastle.X509.X509Certificate[] {
        DotNetUtilities.FromX509Certificate(certificate)
      };
      // Creating the signature
      IExternalSignature externalSignature = new X509Certificate2Signature(certificate, "SHA-1");
      signer.SignDetached(externalSignature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
      return true;
    }
    /*
    static public void Main()
    {
      // Access Personal (MY) certificate store of current user
      X509Store myCertStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
      myCertStore.Open(OpenFlags.ReadOnly);
      // Find the certificate we'll use to sign
      X509Certificate2 certificate = null;
      foreach (X509Certificate2 cert in myCertStore.Certificates)
      {
        if (cert.GetSerialNumberString().Equals("392320071752B5EE"))
        {
          certificate = cert;
          break;
        }
      }
      PdfReader reader = new PdfReader("C:/Users/diego.WIN-ORSG2IMDBS1/Desktop/document.pdf");
      StampingProperties properties = new StampingProperties();
      properties.UseAppendMode();
      PdfSigner signer = new PdfSigner(reader, new FileStream("C:/Users/diego.WIN-ORSG2IMDBS1/Desktop/signed.pdf", FileMode.Create), properties);
      signer.SetCertificationLevel(1);
      // Creating the appearance
      var pdfBox = signer.GetDocument().GetPage(1).GetMediaBox();
      var x = 0.010025062656641603f;
      var y = 0.01559792027729636f;
      var width = 0.24686716791979949f * pdfBox.GetWidth();
      var height = 0.08979202772963605f * pdfBox.GetHeight();
      Console.WriteLine(
        "x: " + (pdfBox.GetWidth() * x).ToString() +
        "\ny: " + (pdfBox.GetHeight() * (1 - y) - height).ToString() +
        "\nwidth: " + width +
        "\nheight: " + height +
        "\npdfWidth: " + pdfBox.GetWidth() +
        "\npdfHeight: " + pdfBox.GetHeight()
      );
      PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
        .SetPageRect(new iText.Kernel.Geom.Rectangle(
          pdfBox.GetWidth() * x, pdfBox.GetHeight() * (1 - y) - height,
          width, height
        ))
        .SetPageNumber(1)
        .SetLayer2Text(
          "Assinado de forma digital em " + System.DateTime.Now.ToString()
        )
        .SetLayer2FontSize(10)
        .SetRenderingMode(PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION);
      // Get Chain
      var chain = new Org.BouncyCastle.X509.X509Certificate[] {
        DotNetUtilities.FromX509Certificate(certificate)
      };
      // Creating the signature
      IExternalSignature externalSignature = new X509Certificate2Signature(certificate, "SHA-1");
      signer.SignDetached(externalSignature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }
    */
  }
}