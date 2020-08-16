using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using Xunit;

namespace Tests.Tls
{
    public class ClientHelloTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetResultHexString();
            var buffer = new byte[TlsBuffer.MaxRecordSize];
            var random = HandshakeRandom.Parse(GetBytesOfRandom(), out _);
            var cipherSuite = CipherSuite.CreateFromList(Cipher.TLS_AES_128_GCM_SHA256, Cipher.TLS_AES_256_GCM_SHA384, Cipher.TLS_CHACHA20_POLY1305_SHA256);
            var sessionId = SessionId.Parse(GetBytesOfSessionId(), out _);

            //Act
            var cursor = buffer.AsSpan();
            var context = ClientHello.StartWriting(ref cursor, random, cipherSuite, sessionId);

            ServerNameExtension.WriteHostName(ref cursor, "example.ulfheim.net");
            SupportedGroupsExtension.WriteFromList(ref cursor, NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1);
            SignatureAlgorithmsExtension.WriteFromList(ref cursor,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                SignatureScheme.RSA_PSS_RSAE_SHA256,
                SignatureScheme.RSA_PKCS1_SHA256,
                SignatureScheme.ECDSA_SECP384R1_SHA384,
                SignatureScheme.RSA_PSS_RSAE_SHA384,
                SignatureScheme.RSA_PKCS1_SHA386,
                SignatureScheme.RSA_PSS_RSAE_SHA512,
                SignatureScheme.RSA_PKCS1_SHA512,
                SignatureScheme.RSA_PKCS1_SHA1);

            context.Complete(ref cursor);

            Array.Resize(ref buffer, buffer.Length - cursor.Length);

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(buffer));
        }

        private string GetResultHexString()
        {
            return "010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304";
        }

        private byte[] GetBytesOfRandom()
        {
            return Utils.ParseHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        }

        private byte[] GetBytesOfSessionId()
        {
            return Utils.ParseHexString("20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        }
    }
}
