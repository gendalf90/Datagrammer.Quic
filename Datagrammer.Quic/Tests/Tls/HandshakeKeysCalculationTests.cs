using Datagrammer.Quic.Protocol.Tls;
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
        [InlineData("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624", "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a")]
        public void CreateHandshakeSecret_TlsAes128GcmSha256_ResultIsExpected(string sharedSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var sharedSecretBytes = Utils.ParseHexString(sharedSecret);

            //Act
            var result = hash.CreateHandshakeSecret(sharedSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a", "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5", "ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea")]
        public void CreateClientHandshakeTrafficSecret_TlsAes128GcmSha256_ResultIsExpected(string handshakeSecret, string helloHash, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeSecretBytes = Utils.ParseHexString(handshakeSecret);
            var helloHashBytes = Utils.ParseHexString(helloHash);

            //Act
            var result = hash.CreateClientHandshakeTrafficSecret(handshakeSecretBytes, helloHashBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a", "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5", "a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814")]
        public void CreateServerHandshakeTrafficSecret_TlsAes128GcmSha256_ResultIsExpected(string handshakeSecret, string helloHash, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeSecretBytes = Utils.ParseHexString(handshakeSecret);
            var helloHashBytes = Utils.ParseHexString(helloHash);

            //Act
            var result = hash.CreateServerHandshakeTrafficSecret(handshakeSecretBytes, helloHashBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea", "7154f314e6be7dc008df2c832baa1d39")]
        [InlineData("a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814", "844780a7acad9f980fa25c114e43402a")]
        public void CreateHandshakeKey_TlsAes128GcmSha256_ResultIsExpected(string handshakeTrafficSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeTrafficSecretBytes = Utils.ParseHexString(handshakeTrafficSecret);

            //Act
            var result = hash.CreateHandshakeKey(handshakeTrafficSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea", "71abc2cae4c699d47c600268")]
        [InlineData("a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814", "4c042ddc120a38d1417fc815")]
        public void CreateHandshakeIv_TlsAes128GcmSha256_ResultIsExpected(string handshakeTrafficSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeTrafficSecretBytes = Utils.ParseHexString(handshakeTrafficSecret);

            //Act
            var result = hash.CreateHandshakeIv(handshakeTrafficSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }
    }
}
