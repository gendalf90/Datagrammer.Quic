using Datagrammer.Quic.Protocol.Tls;
using Xunit;

namespace Tests.Tls
{
    public class VerifyDataTests
    {
        [Fact]
        public void CalculateVerifyData_ResultIsExpected()
        {
            //Arrange
            var expected = GetVerifyData();
            var handshakeSecret = GetHandshakeSecret();
            var finalHash = GetFinalHash();

            //Act
            var hash = SignatureScheme.RSA_PKCS1_SHA256.GetHash();
            var result = hash.CreateVerifyData(Utils.ParseHexString(handshakeSecret), Utils.ParseHexString(finalHash));

            //Assert
            Assert.Equal(expected, Utils.ToHexString(result.ToArray()), true);
        }

        private string GetHandshakeSecret()
        {
            return "a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814";
        }

        private string GetFinalHash()
        {
            return "0cd9871cd7a164dce9fbc7f96c0f2978417dfc0c728a3f2096a7de210991a865";
        }

        private string GetVerifyData()
        {
            return "ea6ee176dccc4af1859e9e4e93f797eac9a78ce439301e35275ad43f3cddbde3";
        }
    }
}
