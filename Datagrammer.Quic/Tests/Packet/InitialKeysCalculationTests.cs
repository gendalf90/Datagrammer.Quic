using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Packet
{
    public class InitialKeysCalculationTests
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
    }
}
