using Datagrammer.Quic.Protocol.Tls;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Tls
{
    public class ClientKeyExchangeGenerationTests
    {
        [Theory]
        [InlineData(3)]
        public void GeneratePrivateKey_x25519_GeneratedPrivateKeysAreUnique256Bits(int count)
        {
            //Arrange
            var privateKeys = new List<byte[]>();

            //Act
            for(int i = 0; i < count; i++)
            {
                privateKeys.Add(NamedGroup.X25519.GeneratePrivateKey().ToArray());
            }
            
            //Assert
            Assert.True(privateKeys.TrueForAll(key => key.Length == 32));
            Assert.Equal(count, privateKeys
                .Select(Utils.ToHexString)
                .Distinct()
                .Count());
        }

        [Theory]
        [InlineData("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")]
        public void GeneratePubliceKey_x25519_GeneratedPublicKeyIsExpected(string privateKey, string expectedPublicKey)
        {
            //Arrange
            var privateKeyBytes = Utils.ParseHexString(privateKey);

            //Act
            var result = NamedGroup.X25519.GeneratePublicKey(privateKeyBytes).ToArray();

            //Assert
            Assert.Equal(expectedPublicKey, Utils.ToHexString(result), true);
        }
    }
}
