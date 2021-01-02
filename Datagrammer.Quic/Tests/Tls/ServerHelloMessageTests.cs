using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using Xunit;
using TlsRecord = Datagrammer.Quic.Protocol.Tls.Record;

namespace Tests.Tls
{
    public class ServerHelloMessageTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHexString();
            var buffer = new byte[TlsBuffer.MaxRecordSize];
            var random = HandshakeRandom.Parse(GetBytesOfRandom());
            var sessionId = SessionId.Parse(GetBytesOfSessionId());

            //Act
            var cursor = new MemoryCursor(buffer);

            using (TlsRecord.StartWriting(cursor, RecordType.Handshake, ProtocolVersion.Tls12))
            using (ServerHello.StartWriting(cursor, random, Cipher.TLS_AES_128_GCM_SHA256, sessionId))
            {
                using (cursor.StartKeyShareWriting())
                {
                    using (KeyShareEntry.StartWriting(cursor, NamedGroup.X25519))
                    {
                        GetBytesOfPublicKey().CopyTo(cursor);
                    }
                }

                using (cursor.StartSupportedVersionWriting())
                {
                    ProtocolVersion.Tls13.WriteBytes(cursor);
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Read_ResultsAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetMessageHexString());
            var record = new TlsRecord();
            var message = new ServerHello();
            var keyShareEntry = new KeyShareEntry();
            var supportedVersion = new ProtocolVersion();

            //Act
            var cursor = new MemoryCursor(messageBytes);
            var result = TlsRecord.TryParse(cursor, RecordType.Handshake, out record);

            using (record.Payload.SetCursor(cursor))
            {
                result &= ServerHello.TryParse(cursor, out message);

                using (message.Payload.SetCursor(cursor))
                {
                    result &= cursor.TryParseKeyShare(out var keyShareBuffer);
                    using (keyShareBuffer.SetCursor(cursor))
                    {
                        keyShareEntry = KeyShareEntry.Parse(cursor);
                    }

                    result &= cursor.TryParseSupportedVersion(out var supportedVersionBuffer);
                    using (supportedVersionBuffer.SetCursor(cursor))
                    {
                        supportedVersion = ProtocolVersion.Parse(cursor);
                    }

                    result &= cursor.IsEnd();
                }

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(RecordType.Handshake, record.Type);
            Assert.Equal(ProtocolVersion.Tls12, record.ProtocolVersion);
            Assert.Equal(HandshakeRandom.Parse(GetBytesOfRandom()), message.Random);
            Assert.Equal(SessionId.Parse(GetBytesOfSessionId()), message.SessionId);
            Assert.Equal(Cipher.TLS_AES_128_GCM_SHA256, message.Cipher);
            Assert.Equal(NamedGroup.X25519, keyShareEntry.Group);
            Assert.True(GetBytesOfPublicKey().AsSpan().SequenceEqual(keyShareEntry.Key.Slice(cursor).Span));
            Assert.Equal(ProtocolVersion.Tls13, supportedVersion);
        }

        private string GetMessageHexString()
        {
            return "160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615002b00020304";
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
