﻿using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Tls
{
    public class HandshakeKeysCalculationTests
    {
        [Theory]
        [InlineData("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")]
        [InlineData("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")]
        public void GenerateSharedSecret_x25519_ResultIsExpected(string publicKey, string privateKey, string expectedResult)
        {
            //Arrange
            var curve = NamedGroup.X25519.GetCurve();
            var publicKeyBytes = Utils.ParseHexString(publicKey);
            var privateKeyBytes = Utils.ParseHexString(privateKey);

            //Act
            var result = curve.GenerateSharedSecret(privateKeyBytes, publicKeyBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData(
            "010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304",
            "020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304",
            "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5")]
        public void ComputeHelloMessagesHash_TlsAes128GcmSha256_ResultIsExpected(string clientHelloMessage, string serverHelloMessage, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var amountOfMessageBytes = Utils.ParseHexString(clientHelloMessage + serverHelloMessage);

            //Act
            var result = hash.CreateHash(amountOfMessageBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814", "0cd9871cd7a164dce9fbc7f96c0f2978417dfc0c728a3f2096a7de210991a865", "ea6ee176dccc4af1859e9e4e93f797eac9a78ce439301e35275ad43f3cddbde3")]
        [InlineData("ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea", "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b", "976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b")]
        public void CalculateVerifyData_RsaPkcs1Sha256_ResultIsExpected(string trafficSecret, string finishedHash, string expectedResult)
        {
            //Arrange
            //Act
            var hash = SignatureScheme.RSA_PKCS1_SHA256.GetHash();
            var result = hash.CreateVerifyData(Utils.ParseHexString(trafficSecret), Utils.ParseHexString(finishedHash));

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result.ToArray()), true);
        }

        [Theory]
        [InlineData(
            "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624",
            "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5",
            "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a",
            "ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea",
            "7154f314e6be7dc008df2c832baa1d39",
            "71abc2cae4c699d47c600268")]
        public void CreateClientHandshakeSecrets_TlsAes128GcmSha256_ResultIsExpected(
            string sharedSecret,
            string helloHash,
            string resultHandshake,
            string resultTraffic,
            string resultKey,
            string resultIv)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var sharedSecretBytes = Utils.ParseHexString(sharedSecret);
            var helloHashBytes = Utils.ParseHexString(helloHash);

            //Act
            var result = hash.CreateClientHandshakeSecrets(sharedSecretBytes, helloHashBytes);

            //Assert
            Assert.Equal(resultHandshake, Utils.ToHexString(result.HandshakeSecret.ToArray()), true);
            Assert.Equal(resultTraffic, Utils.ToHexString(result.TrafficSecret.ToArray()), true);
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
        }

        [Theory]
        [InlineData(
            "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624",
            "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5",
            "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a",
            "a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814",
            "844780a7acad9f980fa25c114e43402a",
            "4c042ddc120a38d1417fc815")]
        public void CreateServerHandshakeSecrets_TlsAes128GcmSha256_ResultIsExpected(
            string sharedSecret,
            string helloHash,
            string resultHandshake,
            string resultTraffic,
            string resultKey,
            string resultIv)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var sharedSecretBytes = Utils.ParseHexString(sharedSecret);
            var helloHashBytes = Utils.ParseHexString(helloHash);

            //Act
            var result = hash.CreateServerHandshakeSecrets(sharedSecretBytes, helloHashBytes);

            //Assert
            Assert.Equal(resultHandshake, Utils.ToHexString(result.HandshakeSecret.ToArray()), true);
            Assert.Equal(resultTraffic, Utils.ToHexString(result.TrafficSecret.ToArray()), true);
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
        }
    }
}
