using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Tls
{
    public class ApplicationKeysCalculationTests
    {
        [Theory]
        [InlineData("fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a", "7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d")]
        public void GenerateMasterSecret_TlsAes128GcmSha256_ResultIsExpected(string handshakeSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeSecretBytes = Utils.ParseHexString(handshakeSecret);

            //Act
            var result = hash.CreateMasterSecret(handshakeSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d", "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b", "b8822231c1d676ecca1c11fff6594280314d03a4e91cf1af7fe73f8f7be2c11b")]
        public void CreateClientApplicationTrafficSecret_TlsAes128GcmSha256_ResultIsExpected(string masterSecret, string handshakeHash, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var secretBytes = Utils.ParseHexString(masterSecret);
            var hashBytes = Utils.ParseHexString(handshakeHash);

            //Act
            var result = hash.CreateClientApplicationTrafficSecret(secretBytes, hashBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d", "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b", "3fc35ea70693069a277956afa23b8f4543ce68ac595f2aace05cd7a1c92023d5")]
        public void CreateServerApplicationTrafficSecret_TlsAes128GcmSha256_ResultIsExpected(string masterSecret, string handshakeHash, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var secretBytes = Utils.ParseHexString(masterSecret);
            var hashBytes = Utils.ParseHexString(handshakeHash);

            //Act
            var result = hash.CreateServerApplicationTrafficSecret(secretBytes, hashBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("b8822231c1d676ecca1c11fff6594280314d03a4e91cf1af7fe73f8f7be2c11b", "49134b95328f279f0183860589ac6707")]
        [InlineData("3fc35ea70693069a277956afa23b8f4543ce68ac595f2aace05cd7a1c92023d5", "0b6d22c8ff68097ea871c672073773bf")]
        public void CreateApplicationKey_TlsAes128GcmSha256_ResultIsExpected(string trafficSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var trafficSecretBytes = Utils.ParseHexString(trafficSecret);

            //Act
            var result = hash.CreateKey(trafficSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData("b8822231c1d676ecca1c11fff6594280314d03a4e91cf1af7fe73f8f7be2c11b", "bc4dd5f7b98acff85466261d")]
        [InlineData("3fc35ea70693069a277956afa23b8f4543ce68ac595f2aace05cd7a1c92023d5", "1b13dd9f8d8f17091d34b349")]
        public void CreateApplicationIv_TlsAes128GcmSha256_ResultIsExpected(string trafficSecret, string expectedResult)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var trafficSecretBytes = Utils.ParseHexString(trafficSecret);

            //Act
            var result = hash.CreateIv(trafficSecretBytes).ToArray();

            //Assert
            Assert.Equal(expectedResult, Utils.ToHexString(result), true);
        }

        [Theory]
        [InlineData(
            "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a",
            "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b",
            "7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d",
            "b8822231c1d676ecca1c11fff6594280314d03a4e91cf1af7fe73f8f7be2c11b",
            "49134b95328f279f0183860589ac6707",
            "bc4dd5f7b98acff85466261d")]
        public void CreateClientApplicationSecrets_TlsAes128GcmSha256_ResultIsExpected(
            string handshakeSecret, 
            string handshakeHash, 
            string resultMaster, 
            string resultTraffic, 
            string resultKey, 
            string resultIv)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeSecretBytes = Utils.ParseHexString(handshakeSecret);
            var handshakeHashBytes = Utils.ParseHexString(handshakeHash);

            //Act
            var result = hash.CreateClientApplicationSecrets(handshakeSecretBytes, handshakeHashBytes);

            //Assert
            Assert.Equal(resultMaster, Utils.ToHexString(result.MasterSecret.ToArray()), true);
            Assert.Equal(resultTraffic, Utils.ToHexString(result.TrafficSecret.ToArray()), true);
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
        }

        [Theory]
        [InlineData(
            "fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a",
            "22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b",
            "7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d",
            "3fc35ea70693069a277956afa23b8f4543ce68ac595f2aace05cd7a1c92023d5",
            "0b6d22c8ff68097ea871c672073773bf",
            "1b13dd9f8d8f17091d34b349")]
        public void CreateServerApplicationSecrets_TlsAes128GcmSha256_ResultIsExpected(
            string handshakeSecret,
            string handshakeHash,
            string resultMaster,
            string resultTraffic,
            string resultKey,
            string resultIv)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var handshakeSecretBytes = Utils.ParseHexString(handshakeSecret);
            var handshakeHashBytes = Utils.ParseHexString(handshakeHash);

            //Act
            var result = hash.CreateServerApplicationSecrets(handshakeSecretBytes, handshakeHashBytes);

            //Assert
            Assert.Equal(resultMaster, Utils.ToHexString(result.MasterSecret.ToArray()), true);
            Assert.Equal(resultTraffic, Utils.ToHexString(result.TrafficSecret.ToArray()), true);
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
        }
    }
}
