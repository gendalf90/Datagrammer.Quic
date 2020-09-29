using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Curves;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Tls
{
    public class KeyExchangeGenerationTests
    {
        [Theory]
        [InlineData(3)]
        public void GeneratePrivateKey_x25519_GeneratedPrivateKeysAreUnique256Bits(int count)
        {
            //Arrange
            var curve = NamedGroup.X25519.GetCurve();
            var privateKeys = new List<byte[]>();

            //Act
            for(int i = 0; i < count; i++)
            {
                privateKeys.Add(curve.GeneratePrivateKey().ToArray());
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
        [InlineData("909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615")]
        public void GeneratePubliceKey_x25519_GeneratedPublicKeyIsExpected(string privateKey, string expectedPublicKey)
        {
            //Arrange
            var curve = NamedGroup.X25519.GetCurve();
            var privateKeyBytes = Utils.ParseHexString(privateKey);

            //Act
            var result = curve.GeneratePublicKey(privateKeyBytes).ToArray();

            //Assert
            Assert.Equal(expectedPublicKey, Utils.ToHexString(result), true);
        }
    }
}
