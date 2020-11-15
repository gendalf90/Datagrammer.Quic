using Datagrammer.Quic.Protocol.Tls;
using System;
using Xunit;

namespace Tests.Tls
{
    public class CertificateVerifyMessageTests
    {
        [Fact]
        public void Write_ResultIsExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHexString();
            var signatureBytes = Utils.ParseHexString(GetSignatureHexDataString());
            var scheme = SignatureScheme.RSA_PSS_RSAE_SHA256;
            var buffer = new byte[TlsBuffer.MaxRecordSize];

            //Act
            var cursor = buffer.AsSpan();
            var context = CertificateVerify.StartWriting(ref cursor, scheme);

            signatureBytes.CopyTo(cursor);
            cursor = cursor.Slice(signatureBytes.Length);

            context.Complete(ref cursor);

            Array.Resize(ref buffer, buffer.Length - cursor.Length);

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(buffer), true);
        }

        [Fact]
        public void Read_HasOneCertificateInList_CertificateIsExpected()
        {
            //Arrange
            var expectedSignature = GetSignatureHexDataString();
            var expectedScheme = SignatureScheme.RSA_PSS_RSAE_SHA256;
            var messageBytes = Utils.ParseHexString(GetMessageHexString());

            //Act
            var result = CertificateVerify.TryParse(messageBytes, out var message, out var remainings);

            //Assert
            Assert.True(result);
            Assert.True(remainings.IsEmpty);
            Assert.Equal(expectedSignature, Utils.ToHexString(message.Signature.ToArray()), true);
            Assert.Equal(expectedScheme, message.Scheme);
        }

        private string GetMessageHexString()
        {
            return "0f0001040804010017feb533ca6d007d0058257968424bbc3aa6909e9d49557576a520e04a5ef05f0e86d24ff43f8eb861eef595228d7032aa360f714e667413926ef4f8b5803b69e35519e3b23f4373dfac6787066dcb4756b54560e0886e9b962c4ad28dab26bad1abc25916b09af286537f684f808aefee73046cb7df0a84fbb5967aca131f4b1cf389799403a30c02d29cbdadb72512db9cec2e5e1d00e50cafcf6f21091ebc4f253c5eab01a679baeabeedb9c9618f66006b8244d6622aaa56887ccfc66a0f3851dfa13a78cff7991e03cb2c3a0ed87d7367362eb7805b00b2524ff298a4da487cacdeaf8a2336c5631b3efa935bb411e753ca13b015fec7e4a730f1369f9e";
        }

        private string GetSignatureHexDataString()
        {
            return "17feb533ca6d007d0058257968424bbc3aa6909e9d49557576a520e04a5ef05f0e86d24ff43f8eb861eef595228d7032aa360f714e667413926ef4f8b5803b69e35519e3b23f4373dfac6787066dcb4756b54560e0886e9b962c4ad28dab26bad1abc25916b09af286537f684f808aefee73046cb7df0a84fbb5967aca131f4b1cf389799403a30c02d29cbdadb72512db9cec2e5e1d00e50cafcf6f21091ebc4f253c5eab01a679baeabeedb9c9618f66006b8244d6622aaa56887ccfc66a0f3851dfa13a78cff7991e03cb2c3a0ed87d7367362eb7805b00b2524ff298a4da487cacdeaf8a2336c5631b3efa935bb411e753ca13b015fec7e4a730f1369f9e";
        }
    }
}
