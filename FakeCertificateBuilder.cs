using System.Globalization;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace KonturCertAuthDown;

internal static class FakeCertificateBuilder
{
    private static readonly string DigestAlgorithm = PkcsObjectIdentifiers.Sha512WithRsaEncryption.ToString();
    private static readonly SecureRandom SecureRandom = new();

    public static string BuildBase64EncodedCertificate(int randomBase64StringBytesCount)
    {
        var rootCa = CreateRootCaCertificate();
        var ca = CreateCaCertificate(rootCa);
        var resultCertificate = CreateCertificate(rootCa, ca, randomBase64StringBytesCount);
        var cer = resultCertificate.Certificate.GetEncoded();
        var result = Convert.ToBase64String(cer);
        return result;
    }

    private static string GenerateRandomBase64String(int bytesCount)
    {
        return Convert.ToBase64String(SecureRandom.GenerateSeed(bytesCount));
    }

    private static CertificateInfo CreateCaCertificate(CertificateInfo rootCa)
    {
        var parameters = new CertificateParameters
        {
            NameAttributes = new CertificateX509NameAttribute[]
            {
                new(X509Name.CN, "ООО \"КОМПАНИЯ \"ТЕНЗОР\""), /* Common name */
                new(X509Name.O, "ООО \"КОМПАНИЯ \"ТЕНЗОР\""), /* organization */
                new(X509Name.OU, "Удостоверяющий центр"), /* organization unit name */
                new(X509Name.Street, "Московский проспект, д. 12"),
                new(X509Name.L, "г. Ярославль"), /* locality name */
                new(X509Name.ST, "76 Ярославская область"), /* state, or province name */
                new(X509Name.C, "RU"), /* country code */
                new("1.2.643.3.131.1.1", new DerNumericString("007605016030")), /* "INN" Individual Taxpayer Number (ITN) */
                new("1.2.643.100.1", new DerNumericString("1027600787994")), /* "OGRN" main state registration number of juridical entities */
                new(X509Name.EmailAddress, "ca_tensor@tensor.ru")
            },
            SerialNumber = new BigInteger("61e7cdaa00000000051a", 16),
            KeyPair = GenerateEcKeyPair(SecObjectIdentifiers.SecP256r1),
            ValidFromUtc = DateTime.Parse("2020-12-29T07:26:13", styles: DateTimeStyles.AssumeUniversal),
            ValidToUtc = DateTime.Parse("2035-12-29T07:26:13", styles: DateTimeStyles.AssumeUniversal),
            Extensions = new CertificateExtension[]
            {
                new(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign /* 0x86*/)),
                new(
                    X509Extensions.SubjectKeyIdentifier,
                    false,
                    new SubjectKeyIdentifier(new DerOctetString(new BigInteger("57de2319ef81812c0cd71efce7cdb4b64021f132", 16).ToByteArrayUnsigned()))
                ),
                new(X509Extensions.BasicConstraints, true, BasicConstraints.GetInstance(new DerSequence(DerBoolean.True, new DerInteger(0)))),
                new(
                    X509Extensions.CertificatePolicies,
                    false,
                    new CertificatePolicies(new PolicyInformation[]
                        {
                            new(new DerObjectIdentifier("1.2.643.100.113.1")), /*"KC1" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.2")), /*"KC2" class of cryptographic token*/
                            new(new DerObjectIdentifier("2.5.29.32.0")) /*Any policy*/
                        }
                    )
                ),
                new(
                    "1.2.643.100.111", /* Owner's electronic signature tool (token or software type) */
                    false,
                    new DerUtf8String("\"КриптоПро CSP\" версия 4.0 (исполнение 2-Base)")
                ),
                new(
                    "1.3.6.1.4.1.311.20.2", /*Certificate type extension: szOID_ENROLL_CERTTYPE_EXTENSION*/
                    false,
                    new DerUtf8String("SubCA")
                ),
                new(
                    "1.3.6.1.4.1.311.21.1", /*Certificate services Certification Authority (CA) version*/
                    false,
                    new DerInteger(0)
                ),
                new(
                    X509Extensions.AuthorityKeyIdentifier,
                    false,
                    new AuthorityKeyIdentifier(
                        new BigInteger("c254f1b46bd44cb7e06d36b42390f1fec33c9b06", 16).ToByteArrayUnsigned(),
                        new GeneralNames(new GeneralName(rootCa.Parameters.X509Name)),
                        rootCa.Parameters.SerialNumber)
                ),
                new(
                    X509Extensions.CrlDistributionPoints,
                    false,
                    new CrlDistPoint(new[]
                    {
                        new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(6, "http://reestr-pki.ru/cdp/guc_gost12.crl"))), null,
                            null),
                        new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(6, "http://company.rt.ru/cdp/guc_gost12.crl"))), null,
                            null),
                        new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(6, "http://rostelecom.ru/cdp/guc_gost12.crl"))), null,
                            null)
                    })
                ),
                new(
                    X509Extensions.AuthorityInfoAccess,
                    false,
                    new AuthorityInformationAccess(new AccessDescription(AccessDescription.IdADCAIssuers,
                        new GeneralName(6, "http://reestr-pki.ru/cdp/guc_gost12.crt")))
                ),
                new(
                    "1.2.643.100.112", /* Tools used to generate key pairs and tools used by the Certificate Authority (CA )to sign certificates */
                    false,
                    new DerSequence(
                        new DerUtf8String("ПАКМ «КриптоПро HSM» версии 2.0"),
                        new DerUtf8String("ПАК «Головной удостоверяющий центр»"),
                        new DerUtf8String("Заключение № 149/3/2/2/23 от 02.03.2018"),
                        new DerUtf8String("Заключение № 149/7/6/105 от 27.06.2018")
                    )
                )
            }
        };

        var cert = GenerateCertificate(parameters, rootCa.Parameters);

        return new CertificateInfo("ca", parameters, cert);
    }

    private static DerNumericString GenerateRandomDerNumericString(int count)
    {
        var chars = SecureRandom.GenerateSeed(count).Select(b => (b % 10).ToString()[0]).ToArray();
        var result = new string(chars);
        return new DerNumericString(result);
    }

    private static CertificateInfo CreateCertificate(CertificateInfo rootCa, CertificateInfo ca, int randomBase64StringBytesCount)
    {
        var serialNumber = BigInteger.ProbablePrime(20 * 8, SecureRandom);
        var parameters = new CertificateParameters
        {
            NameAttributes = new CertificateX509NameAttribute[]
            {
                new("1.2.643.100.1", GenerateRandomDerNumericString(13)), /* "OGRN" main state registration number of juridical entities */
                new("1.2.643.100.3", GenerateRandomDerNumericString(11)), /* "SNILS" individual insurance account number */
                new("1.2.643.3.131.1.1", GenerateRandomDerNumericString(12)), /* "INN" Individual Taxpayer Number (ITN) */
                new(X509Name.EmailAddress, $"slave{SecureRandom.Next(1, 10000)}@pumps.transneft.ru"),
                new(X509Name.O, GenerateRandomBase64String(randomBase64StringBytesCount)), /* organization */
                new(X509Name.T, GenerateRandomBase64String(randomBase64StringBytesCount)), /* title */
                new(X509Name.CN, GenerateRandomBase64String(randomBase64StringBytesCount)), /* Common name */
                new(X509Name.Surname, GenerateRandomBase64String(randomBase64StringBytesCount)),
                new(X509Name.GivenName, GenerateRandomBase64String(randomBase64StringBytesCount)),
                new(X509Name.C, "RU"), /* country code */
                new(X509Name.L, GenerateRandomBase64String(randomBase64StringBytesCount)), /* locality name */
                new(X509Name.ST, GenerateRandomBase64String(randomBase64StringBytesCount)), /* state, or province name */
                new(X509Name.Street, GenerateRandomBase64String(randomBase64StringBytesCount))
            },
            SerialNumber = serialNumber,
            KeyPair = GenerateEcKeyPair(SecObjectIdentifiers.SecP256r1),
            ValidFromUtc = DateTime.Parse("2022-02-08T09:20:54", styles: DateTimeStyles.AssumeUniversal),
            ValidToUtc = DateTime.Parse("2023-02-08T09:30:54", styles: DateTimeStyles.AssumeUniversal),
            Extensions = new CertificateExtension[]
            {
                new(X509Extensions.KeyUsage, true, new KeyUsage(0xf8)),
                new(
                    X509Extensions.ExtendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(new[]
                    {
                        new DerObjectIdentifier("1.2.643.2.2.34.25"), /* "UC" time stamp service user */
                        new DerObjectIdentifier("1.2.643.2.2.34.26"), /* "UC" user of the service of actual statuses */
                        new DerObjectIdentifier(
                            "1.2.643.2.2.34.6"), /* Electronic digital signature of electronic documents defined by the Regulations for the Certification Center User */
                        new DerObjectIdentifier(
                            "1.2.643.3.58.3.1.1.5"), /* Error: One or more errors occurred. (Call failed with status code 404 (Not Found): GET http://oid-info.com/get/1.2.643.3.58.3.1.1.5) */
                        new DerObjectIdentifier("1.3.6.1.5.5.7.3.2"), /* Transport Layer Security (TLS) World Wide Web (WWW) client authentication */
                        new DerObjectIdentifier("1.3.6.1.5.5.7.3.4") /* Email protection */
                    })
                ),
                new(
                    X509Extensions.CertificatePolicies,
                    false,
                    new CertificatePolicies(new PolicyInformation[]
                        {
                            new(new DerObjectIdentifier("1.2.643.100.113.1")), /*"KC1" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.2")) /*"KC2" class of cryptographic token*/
                        }
                    )
                ),
                new(
                    "1.2.643.100.111", /* Owner's electronic signature tool (token or software type) */
                    false,
                    new DerUtf8String("КриптоПро CSP")
                ),
                new(
                    X509Extensions.SubjectAlternativeName,
                    false,
                    new DerSequence(
                        new DerTaggedObject(
                            4,
                            new DerSequence(
                                new DerSet(
                                    new DerSequence(
                                        new DerObjectIdentifier("1.2.840.113549.1.9.2"), /* PKCS#9 unstructuredName */
                                        new DerIA5String("INN=7449139434/KPP=744901001/OGRN=1197456028604")
                                    )
                                )
                            )
                        )
                    )
                ),
                new(
                    X509Extensions.AuthorityInfoAccess,
                    false,
                    new AuthorityInformationAccess(new[]
                    {
                        new AccessDescription(AccessDescription.IdADOcsp, new GeneralName(6, "http://tax4.tensor.ru/ocsp-tensorca-2021_gost2012/ocsp.srf")),
                        new AccessDescription(AccessDescription.IdADCAIssuers,
                            new GeneralName(6, "http://tax4.tensor.ru/tensorca-2021_gost2012/certenroll/tensorca-2021_gost2012.crt")),
                        new AccessDescription(AccessDescription.IdADCAIssuers, new GeneralName(6, "http://tensor.ru/ca/tensorca-2021_gost2012.crt")),
                        new AccessDescription(AccessDescription.IdADCAIssuers, new GeneralName(6, "http://crl.tensor.ru/tax4/ca/tensorca-2021_gost2012.crt")),
                        new AccessDescription(AccessDescription.IdADCAIssuers, new GeneralName(6, "http://crl2.tensor.ru/tax4/ca/tensorca-2021_gost2012.crt")),
                        new AccessDescription(AccessDescription.IdADCAIssuers, new GeneralName(6, "http://crl3.tensor.ru/tax4/ca/tensorca-2021_gost2012.crt"))
                    })
                ),
                new(
                    X509Extensions.PrivateKeyUsagePeriod,
                    false,
                    PrivateKeyUsagePeriod.GetInstance(
                        new DerSequence(
                            new DerTaggedObject(0, new DerGeneralizedTime("20220208092053Z")),
                            new DerTaggedObject(1, new DerGeneralizedTime("20230208092053Z"))
                        )
                    )
                ),
                new(
                    "1.2.643.100.112", /* Tools used to generate key pairs and tools used by the Certificate Authority (CA )to sign certificates */
                    false,
                    new DerSequence(
                        new DerUtf8String("\"КриптоПро CSP\" (версия 4.0)"),
                        new DerUtf8String("\"Удостоверяющий центр \"КриптоПро УЦ\" версии 2.0"),
                        new DerUtf8String("Сертификат соответствия № СФ/124-3380 от 11.05.2018"),
                        new DerUtf8String("Сертификат соответствия № СФ/128-3592 от 17.10.2018")
                    )
                ),
                new(
                    X509Extensions.CrlDistributionPoints,
                    false,
                    new CrlDistPoint(new[]
                    {
                        new DistributionPoint(
                            new DistributionPointName(new GeneralNames(new GeneralName(6,
                                "http://tax4.tensor.ru/tensorca-2021_gost2012/certenroll/tensorca-2021_gost2012.crl"))), null, null),
                        new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(6, "http://tensor.ru/ca/tensorca-2021_gost2012.crl"))),
                            null, null),
                        new DistributionPoint(
                            new DistributionPointName(new GeneralNames(new GeneralName(6, "http://crl.tensor.ru/tax4/ca/crl/tensorca-2021_gost2012.crl"))),
                            null, null),
                        new DistributionPoint(
                            new DistributionPointName(new GeneralNames(new GeneralName(6, "http://crl2.tensor.ru/tax4/ca/crl/tensorca-2021_gost2012.crl"))),
                            null, null),
                        new DistributionPoint(
                            new DistributionPointName(new GeneralNames(new GeneralName(6, "http://crl3.tensor.ru/tax4/ca/crl/tensorca-2021_gost2012.crl"))),
                            null, null)
                    })
                ),
                new(
                    X509Extensions.AuthorityKeyIdentifier,
                    false,
                    new AuthorityKeyIdentifier(
                        new BigInteger("57de2319ef81812c0cd71efce7cdb4b64021f132", 16).ToByteArrayUnsigned(),
                        new GeneralNames(new GeneralName(rootCa.Parameters.X509Name)),
                        ca.Parameters.SerialNumber)
                ),
                new(
                    X509Extensions.SubjectKeyIdentifier,
                    false,
                    new SubjectKeyIdentifier(new DerOctetString(new BigInteger("66f025abb29dfd7714f8999cf3495ed0ff3f9d25", 16).ToByteArrayUnsigned()))
                )
            }
        };

        var cert = GenerateCertificate(parameters, ca.Parameters);

        return new CertificateInfo("cert", parameters, cert);
    }

    private static CertificateInfo CreateRootCaCertificate()
    {
        var parameters = new CertificateParameters
        {
            NameAttributes = new CertificateX509NameAttribute[]
            {
                new(X509Name.CN, "Минкомсвязь России"), /* Common name */
                new("1.2.643.3.131.1.1", new DerNumericString("007710474375")), /* "INN" Individual Taxpayer Number (ITN) */
                new("1.2.643.100.1", new DerNumericString("1047702026701")), /* "OGRN" main state registration number of juridical entities */
                new(X509Name.O, "Минкомсвязь России"), /* organization */
                new(X509Name.Street, "улица Тверская, дом 7"),
                new(X509Name.L, "г. Москва"), /* locality name */
                new(X509Name.ST, "77 Москва"), /* state, or province name */
                new(X509Name.C, "RU"), /* country code */
                new(X509Name.EmailAddress, "dit@minsvyaz.ru")
            },
            SerialNumber = new BigInteger("4e6d478b26f27d657f768e025ce3d393", 16),
            KeyPair = GenerateEcKeyPair(SecObjectIdentifiers.SecP256r1),
            ValidFromUtc = DateTime.Parse("2018-07-06T12:18:06", styles: DateTimeStyles.AssumeUniversal),
            ValidToUtc = DateTime.Parse("2036-07-01T12:18:06", styles: DateTimeStyles.AssumeUniversal),
            Extensions = new CertificateExtension[]
            {
                new(
                    "1.2.643.100.112", /* Tools used to generate key pairs and tools used by the Certificate Authority (CA )to sign certificates */
                    false,
                    new DerSequence(
                        new DerUtf8String("ПАКМ «КриптоПро HSM» версии 2.0"),
                        new DerUtf8String("ПАК «Головной удостоверяющий центр»"),
                        new DerUtf8String("Заключение № 149/3/2/2/23 от 02.03.2018"),
                        new DerUtf8String("Заключение № 149/7/6/105 от 27.06.2018")
                    )
                ),
                new(
                    "1.2.643.100.111", /* Owner's electronic signature tool (token or software type) */
                    false,
                    new DerUtf8String("ПАКМ «КриптоПро HSM» версии 2.0")
                ),
                new(
                    X509Extensions.CertificatePolicies,
                    false,
                    new CertificatePolicies(new PolicyInformation[]
                        {
                            new(new DerObjectIdentifier("1.2.643.100.113.1")), /*"KC1" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.2")), /*"KC2" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.3")), /*"KC3" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.4")), /*"KB1" class of cryptographic token*/
                            new(new DerObjectIdentifier("1.2.643.100.113.5")), /*"KB2" class of cryptographic token*/
                            new(new DerObjectIdentifier("2.5.29.32.0")) /*Any policy*/
                        }
                    )
                ),
                new(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign /* 0x06*/)),
                new(X509Extensions.BasicConstraints, true, new BasicConstraints(true /*CA*/)),
                new(
                    X509Extensions.SubjectKeyIdentifier,
                    false,
                    new SubjectKeyIdentifier(new DerOctetString(new BigInteger("c254f1b46bd44cb7e06d36b42390f1fec33c9b06", 16).ToByteArrayUnsigned()))
                )
            }
        };

        var cert = GenerateCertificate(parameters, parameters);

        return new CertificateInfo("root-ca", parameters, cert);
    }

    private static X509Certificate GenerateCertificate(
        CertificateParameters subjectParameters,
        CertificateParameters issuerParameters)
    {
        ISignatureFactory signatureFactory;
        var issuerPrivate = issuerParameters.KeyPair.Private;
        if (issuerPrivate is ECPrivateKeyParameters)
            signatureFactory = new Asn1SignatureFactory(
                X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                issuerPrivate);
        else
            signatureFactory = new Asn1SignatureFactory(DigestAlgorithm, issuerPrivate);
        var certGenerator = new X509V3CertificateGenerator();

        certGenerator.SetSubjectDN(subjectParameters.X509Name);
        certGenerator.SetSerialNumber(subjectParameters.SerialNumber);
        certGenerator.SetNotBefore(subjectParameters.ValidFromUtc);
        certGenerator.SetNotAfter(subjectParameters.ValidToUtc);
        certGenerator.SetPublicKey(subjectParameters.KeyPair.Public);
        certGenerator.SetIssuerDN(issuerParameters.X509Name);

        foreach (var extension in subjectParameters.Extensions)
            certGenerator.AddExtension(extension.Oid, extension.Critical, extension.Value);

        return certGenerator.Generate(signatureFactory);
    }

    private static AsymmetricCipherKeyPair GenerateEcKeyPair(DerObjectIdentifier curveOid)
    {
        var ecParam = SecNamedCurves.GetByOid(curveOid);
        var ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
        var keygenParam = new ECKeyGenerationParameters(ecDomain, SecureRandom);
        var keyGenerator = new ECKeyPairGenerator();
        keyGenerator.Init(keygenParam);
        return keyGenerator.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
    {
        var keygenParam = new KeyGenerationParameters(SecureRandom, length);
        var keyGenerator = new RsaKeyPairGenerator();
        keyGenerator.Init(keygenParam);
        return keyGenerator.GenerateKeyPair();
    }

    private class CertificateInfo
    {
        public CertificateInfo(string name, CertificateParameters parameters, X509Certificate certificate)
        {
            Parameters = parameters;
            Certificate = certificate;
            Name = name;
        }

        public string Name { get; }

        public CertificateParameters Parameters { get; }

        public X509Certificate Certificate { get; }
    }

    internal class CertificateParameters
    {
        private readonly Lazy<X509Name> _x509Name;

        public CertificateParameters()
        {
            _x509Name = new Lazy<X509Name>(() =>
            {
                return new X509Name(
                    NameAttributes.Select(attribute => attribute.Id).Reverse().ToArray(),
                    NameAttributes.Select(attribute => attribute.Value).Reverse().ToArray()
                );
            });
        }

        public X509Name X509Name => _x509Name.Value;

        public CertificateX509NameAttribute[] NameAttributes { get; set; }

        public BigInteger SerialNumber { get; set; }

        public AsymmetricCipherKeyPair KeyPair { get; set; }

        public DateTime ValidFromUtc { get; set; }

        public DateTime ValidToUtc { get; set; }

        public CertificateExtension[] Extensions { get; set; }
    }

    internal record CertificateX509NameAttribute
    {
        public CertificateX509NameAttribute(string oid, string value)
        {
            Id = new DerObjectIdentifier(oid);
            Value = value;
        }

        public CertificateX509NameAttribute(DerObjectIdentifier oid, string value)
        {
            Id = oid;
            Value = value;
        }

        public CertificateX509NameAttribute(string oid, Asn1Encodable value)
        {
            Id = new DerObjectIdentifier(oid);
            Value = $"#{Hex.ToHexString(value.GetDerEncoded())}";
        }

        public DerObjectIdentifier Id { get; }

        public string Value { get; }
    }

    internal record CertificateExtension
    {
        public CertificateExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable value)
        {
            Oid = oid;
            Critical = critical;
            Value = value;
        }

        public CertificateExtension(string oid, bool critical, Asn1Encodable value)
        {
            Oid = new DerObjectIdentifier(oid);
            Critical = critical;
            Value = value;
        }

        public DerObjectIdentifier Oid { get; }

        public bool Critical { get; }

        public Asn1Encodable Value { get; }
    }
}