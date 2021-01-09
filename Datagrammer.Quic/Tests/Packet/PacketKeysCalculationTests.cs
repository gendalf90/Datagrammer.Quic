using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Packet
{
    public class PacketKeysCalculationTests
    {
        [Theory]
        [InlineData("088394c8f03e515708", "175257a31eb09dea9366d8bb79ad80ba", "6b26114b9cba2b63a9e8dd4f", "9ddd12c994c0698b89374a9c077a3077")]
        public void CreateClientInitialSecrets_TlsAes128GcmSha256_ResultsAreExpected(string destConnectionId, string resultKey, string resultIv, string resultHp)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var connectionId = PacketConnectionId.Parse(Utils.ParseHexString(destConnectionId));

            //Act
            var result = connectionId.CreateClientInitialSecrets(hash);

            //Assert
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
            Assert.Equal(resultHp, Utils.ToHexString(result.Hp.ToArray()), true);
        }

        [Theory]
        [InlineData("088394c8f03e515708", "149d0b1662ab871fbe63c49b5e655a5d", "bab2b12a4c76016ace47856d", "c0c499a65a60024a18a250974ea01dfa")]
        public void CreateServerInitialSecrets_TlsAes128GcmSha256_ResultsAreExpected(string destConnectionId, string resultKey, string resultIv, string resultHp)
        {
            //Arrange
            var hash = Cipher.TLS_AES_128_GCM_SHA256.GetHash();
            var connectionId = PacketConnectionId.Parse(Utils.ParseHexString(destConnectionId));

            //Act
            var result = connectionId.CreateServerInitialSecrets(hash);

            //Assert
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
            Assert.Equal(resultHp, Utils.ToHexString(result.Hp.ToArray()), true);
        }

        [Theory]
        [InlineData(
            "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b", 
            "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8", 
            "e0459b3474bdd0e44a41c144", 
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
            "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")]
        public void CreatePacketSecrets_TlsChaCha20Poly1305Sha256_ResultsAreExpected(string secret, string resultKey, string resultIv, string resultHp, string resultKu)
        {
            //Arrange
            var hash = Cipher.TLS_CHACHA20_POLY1305_SHA256.GetHash();

            //Act
            var result = hash.CreatePacketSecrets(Utils.ParseHexString(secret));

            //Assert
            Assert.Equal(resultKey, Utils.ToHexString(result.Key.ToArray()), true);
            Assert.Equal(resultIv, Utils.ToHexString(result.Iv.ToArray()), true);
            Assert.Equal(resultHp, Utils.ToHexString(result.Hp.ToArray()), true);
            Assert.Equal(resultKu, Utils.ToHexString(result.Ku.ToArray()), true);
        }
    }
}
