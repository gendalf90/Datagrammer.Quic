using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using Xunit;

namespace Tests.Tls.Extensions
{
    public class ServerNameExtensionTests
    {
        [Theory]
        [InlineData("example.ulfheim.net", "0000001800160000136578616d706c652e756c666865696d2e6e6574")]
        public void WriteHostName_WrittenBytesAreExpected(string hostName, string expectedBytes)
        {
            //Arrange
            var buffer = new byte[TlsBuffer.MaxRecordSize];

            //Act
            var cursor = buffer.AsSpan();

            ServerNameExtension.WriteHostName(ref cursor, hostName);

            Array.Resize(ref buffer, buffer.Length - cursor.Length);

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(buffer), true);
        }
    }
}
