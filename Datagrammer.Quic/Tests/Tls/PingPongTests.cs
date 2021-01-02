using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Tls;
using System;
using Xunit;
using TlsRecord = Datagrammer.Quic.Protocol.Tls.Record;

namespace Tests.Tls
{
    public class PingPongTests
    {
        [Theory]
        [InlineData(
            "1703030015c74061535eb12f5f25a781957874742ab7fb305dd5",
            "49134b95328f279f0183860589ac6707",
            "bc4dd5f7b98acff85466261d",
            0,
            "70696e67")]
        [InlineData(
            "1703030015370e5f168afa7fb16b663ecdfca3dbb81931a90ca7",
            "0b6d22c8ff68097ea871c672073773bf",
            "1b13dd9f8d8f17091d34b349",
            1,
            "706f6e67")]
        public void WriteEncryptedApplicationData_TLS_AES_128_GCM_SHA256_ResultIsExpected(string encryptedData, string key, string iv, int seq, string decryptedPayload)
        {
            //Arrange
            var buffer = new byte[TlsBuffer.MaxRecordSize];

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(iv), Utils.ParseHexString(key));

            //Act
            var cursor = new MemoryCursor(buffer);

            using (TlsRecord.StartEncryptedWriting(cursor, RecordType.ApplicationData, aead, seq))
            {
                Utils.ParseHexString(decryptedPayload).CopyTo(cursor);
            }

            //Assert
            Assert.Equal(encryptedData, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Theory]
        [InlineData(
            "1703030015c74061535eb12f5f25a781957874742ab7fb305dd5",
            "49134b95328f279f0183860589ac6707",
            "bc4dd5f7b98acff85466261d",
            0,
            "70696e67")]
        [InlineData(
            "1703030015370e5f168afa7fb16b663ecdfca3dbb81931a90ca7",
            "0b6d22c8ff68097ea871c672073773bf",
            "1b13dd9f8d8f17091d34b349",
            1,
            "706f6e67")]
        public void ReadEncryptedApplicationData_TLS_AES_128_GCM_SHA256_ResultIsExpected(string encryptedData, string key, string iv, int seq, string decryptedPayload)
        {
            //Arrange
            var buffer = Utils.ParseHexString(encryptedData);

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(iv), Utils.ParseHexString(key));

            //Act
            var cursor = new MemoryCursor(buffer);
            var result = TlsRecord.TryParseEncrypted(cursor, aead, seq, out var record);
            var decryptedResult = record.Payload.Slice(cursor);

            //Assert
            Assert.True(result);
            Assert.Equal(decryptedPayload, Utils.ToHexString(decryptedResult.ToArray()), true);
        }
    }
}
