using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Tls;
using System;
using Xunit;
using TlsRecord = Datagrammer.Quic.Protocol.Tls.Record;

namespace Tests.Tls
{
    public class ClientHandshakeFinishedTests
    {
        [Fact]
        public void WriteEncryptedApplicationData_TLS_AES_128_GCM_SHA256_ResultIsExpected()
        {
            //Arrange
            var expectedData = GetEncryptedApplicationData();
            var verifyData = GetVerifyData();
            var encryptionData = GetEncryptionData();
            var buffer = new byte[TlsBuffer.MaxRecordSize];

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(encryptionData.Iv), Utils.ParseHexString(encryptionData.Key));

            //Act
            var cursor = new MemoryCursor(buffer);

            using (TlsRecord.StartEncryptedWriting(cursor, RecordType.Handshake, aead, encryptionData.SeqNum))
            {
                using (Finished.StartWriting(cursor))
                {
                    Utils.ParseHexString(verifyData).CopyTo(cursor);
                }
            }

            //Assert
            Assert.Equal(expectedData, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void ReadEncryptedApplicationData_TLS_AES_128_GCM_SHA256_ResultIsExpected()
        {
            //Arrange
            var messageData = GetEncryptedApplicationData();
            var verifyData = GetVerifyData();
            var encryptionData = GetEncryptionData();
            var parsedVerifyData = new Memory<byte>();

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(encryptionData.Iv), Utils.ParseHexString(encryptionData.Key));

            //Act
            var cursor = new MemoryCursor(Utils.ParseHexString(messageData));
            var result = TlsRecord.TryParseEncrypted(cursor, aead, encryptionData.SeqNum, out var record);

            using (record.Payload.SetCursor(cursor))
            {
                result &= Finished.TryParse(cursor, out var parsedVerifyDataBuffer);
                parsedVerifyData = parsedVerifyDataBuffer.Read(cursor);

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(RecordType.Handshake, record.Type);
            Assert.Equal(ProtocolVersion.Tls12, record.ProtocolVersion);
            Assert.Equal(verifyData, Utils.ToHexString(parsedVerifyData.ToArray()), true);
        }

        private string GetEncryptedApplicationData()
        {
            return "17030300357155dff4741bdfc0c43a1de0b01133ac1974edc88e7091c3ff1e2660cd719283ba40f7c10b5435d4eb22d0536c80c932e2f3c96083";
        }

        private string GetVerifyData()
        {
            return "976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b";
        }

        private (string Iv, string Key, ulong SeqNum) GetEncryptionData()
        {
            return ("71abc2cae4c699d47c600268", "7154f314e6be7dc008df2c832baa1d39", 0);
        }
    }
}
