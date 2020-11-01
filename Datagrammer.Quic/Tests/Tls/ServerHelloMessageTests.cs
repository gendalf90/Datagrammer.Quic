using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using Xunit;

namespace Tests.Tls
{
    public class ServerHelloMessageTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetResultHexString();
            var buffer = new byte[TlsBuffer.MaxRecordSize];
            var random = HandshakeRandom.Parse(GetBytesOfRandom(), out _);
            var cipherSuite = CipherSuite.CreateFromSingle(Cipher.TLS_AES_128_GCM_SHA256);
            var sessionId = SessionId.Parse(GetBytesOfSessionId(), out _);

            //Act
            var cursor = buffer.AsSpan();
            var context = ServerHello.StartWriting(ref cursor, random, cipherSuite, sessionId);

            KeyShareExtension.CreateFromEntry(new KeyShareEntry(NamedGroup.X25519, GetBytesOfPublicKey())).Write(ref cursor);
            SupportedVersionExtension.CreateFromSingle(ProtocolVersion.Tls13).Write(ref cursor);

            context.Complete(ref cursor);

            Array.Resize(ref buffer, buffer.Length - cursor.Length);

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(buffer), true);
        }

        private string GetResultHexString()
        {
            return "020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304";
        }

        private byte[] GetBytesOfRandom()
        {
            return Utils.ParseHexString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f");
        }

        private byte[] GetBytesOfSessionId()
        {
            return Utils.ParseHexString("20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        }

        private byte[] GetBytesOfPublicKey()
        {
            return Utils.ParseHexString("9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615");
        }
    }
}
