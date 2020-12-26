using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Tls;
using Datagrammer.Quic.Protocol.Tls.Extensions;
using System;
using System.Collections.Generic;
using Xunit;
using TlsRecord = Datagrammer.Quic.Protocol.Tls.Record;

namespace Tests.Tls
{
    public class ClientHelloMessageTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHexString();
            var buffer = new byte[TlsBuffer.MaxRecordSize];
            var random = HandshakeRandom.Parse(GetBytesOfRandom());
            var ciphers = new[] { Cipher.TLS_AES_128_GCM_SHA256, Cipher.TLS_AES_256_GCM_SHA384, Cipher.TLS_CHACHA20_POLY1305_SHA256 };
            var sessionId = SessionId.Parse(GetBytesOfSessionId());
            
            //Act
            var cursor = new MemoryCursor(buffer);

            using (TlsRecord.StartWriting(cursor, RecordType.Handshake, ProtocolVersion.Tls10))
            using (ClientHello.StartWriting(cursor, random, ciphers, sessionId))
            {
                using (cursor.StartServerNamesWriting())
                {
                    ServerNameEntry.WriteHostName(cursor, "example.ulfheim.net");
                }

                using (cursor.StartSupportedGroupsWriting())
                {
                    NamedGroup.X25519.WriteBytes(cursor);
                    NamedGroup.SECP256R1.WriteBytes(cursor);
                    NamedGroup.SECP384R1.WriteBytes(cursor);
                }

                using (cursor.StartSignatureAlgorithmsWriting())
                {
                    SignatureScheme.ECDSA_SECP256R1_SHA256.WriteBytes(cursor);
                    SignatureScheme.RSA_PSS_RSAE_SHA256.WriteBytes(cursor);
                    SignatureScheme.RSA_PKCS1_SHA256.WriteBytes(cursor);
                    SignatureScheme.ECDSA_SECP384R1_SHA384.WriteBytes(cursor);
                    SignatureScheme.RSA_PSS_RSAE_SHA384.WriteBytes(cursor);
                    SignatureScheme.RSA_PKCS1_SHA386.WriteBytes(cursor);
                    SignatureScheme.RSA_PSS_RSAE_SHA512.WriteBytes(cursor);
                    SignatureScheme.RSA_PKCS1_SHA512.WriteBytes(cursor);
                    SignatureScheme.RSA_PKCS1_SHA1.WriteBytes(cursor);
                }

                using (cursor.StartKeySharesWriting())
                {
                    using (KeyShareEntry.StartWriting(cursor, NamedGroup.X25519))
                    {
                        GetBytesOfPublicKey().CopyTo(cursor);
                    }
                }

                using (cursor.StartPskKeyExchangeModesWriting())
                {
                    PskKeyExchangeMode.PskDheKe.WriteBytes(cursor);
                }

                using (cursor.StartSupportedVersionsWriting())
                {
                    ProtocolVersion.Tls13.WriteBytes(cursor);
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.Slice().ToArray()), true);
        }

        [Fact]
        public void Read_ResultsAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetMessageHexString());
            var record = new TlsRecord();
            var message = new ClientHello();
            var serverNames = new List<ServerNameEntry>();
            var namedGroups = new List<NamedGroup>();
            var signatureSchemes = new List<SignatureScheme>();
            var keyShareEntries = new List<KeyShareEntry>();
            var pskModes = new List<PskKeyExchangeMode>();
            var supportedVersions = new List<ProtocolVersion>();
            var ciphers = new List<Cipher>();

            //Act
            var cursor = new MemoryCursor(messageBytes);
            var result = TlsRecord.TryParse(cursor, RecordType.Handshake, out record);

            using (record.Payload.SetCursor(cursor))
            {
                result &= ClientHello.TryParse(cursor, out message);

                foreach(var cipher in message.CipherSuite)
                {
                    ciphers.Add(cipher);
                }

                using (message.Payload.SetCursor(cursor))
                {
                    result &= cursor.TryParseServerNames(out var serverNamesBuffer);
                    foreach(var entry in serverNamesBuffer.GetServerNameEntryReader(cursor))
                    {
                        serverNames.Add(entry);
                    }

                    result &= cursor.TryParseSupportedGroups(out var supportedGroupsBuffer);
                    foreach (var group in supportedGroupsBuffer.GetNamedGroupReader(cursor))
                    {
                        namedGroups.Add(group);
                    }

                    result &= cursor.TryParseSignatureAlgorithms(out var signatureAlgorithmsBuffer);
                    foreach(var scheme in signatureAlgorithmsBuffer.GetSignatureSchemeReader(cursor))
                    {
                        signatureSchemes.Add(scheme);
                    }

                    result &= cursor.TryParseKeyShares(out var keySharesBuffer);
                    foreach(var entry in keySharesBuffer.GetKeyShareEntryReader(cursor))
                    {
                        keyShareEntries.Add(entry);
                    }

                    result &= cursor.TryParsePskKeyExchangeModes(out var pskModesBuffer);
                    foreach(var mode in pskModesBuffer.GetPskKeyExchangeModeReader(cursor))
                    {
                        pskModes.Add(mode);
                    }

                    result &= cursor.TryParseSupportedVersions(out var supportedVersionsBuffer);
                    foreach (var version in supportedVersionsBuffer.GetProtocolVersionReader(cursor))
                    {
                        supportedVersions.Add(version);
                    }

                    result &= !cursor.HasNext();
                }

                result &= !cursor.HasNext();
            }

            result &= !cursor.HasNext();

            //Assert
            Assert.True(result);
            Assert.Equal(RecordType.Handshake, record.Type);
            Assert.Equal(ProtocolVersion.Tls10, record.ProtocolVersion);
            Assert.Equal(HandshakeRandom.Parse(GetBytesOfRandom()), message.Random);
            Assert.Equal(SessionId.Parse(GetBytesOfSessionId()), message.SessionId);
            Assert.Equal(new[]
            {
                Cipher.TLS_AES_128_GCM_SHA256,
                Cipher.TLS_AES_256_GCM_SHA384,
                Cipher.TLS_CHACHA20_POLY1305_SHA256
            }, ciphers);
            var serverNameEntry = Assert.Single(serverNames);
            Assert.True(serverNameEntry.IsHostName());
            Assert.Equal("example.ulfheim.net", serverNameEntry.ToString());
            Assert.Equal(new[]
            {
                NamedGroup.X25519,
                NamedGroup.SECP256R1,
                NamedGroup.SECP384R1
            }, namedGroups);
            Assert.Equal(new[]
            {
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                SignatureScheme.RSA_PSS_RSAE_SHA256,
                SignatureScheme.RSA_PKCS1_SHA256,
                SignatureScheme.ECDSA_SECP384R1_SHA384,
                SignatureScheme.RSA_PSS_RSAE_SHA384,
                SignatureScheme.RSA_PKCS1_SHA386,
                SignatureScheme.RSA_PSS_RSAE_SHA512,
                SignatureScheme.RSA_PKCS1_SHA512,
                SignatureScheme.RSA_PKCS1_SHA1
            }, signatureSchemes);
            var keyShareEntry = Assert.Single(keyShareEntries);
            Assert.Equal(NamedGroup.X25519, keyShareEntry.Group);
            Assert.True(GetBytesOfPublicKey().AsSpan().SequenceEqual(keyShareEntry.Key.Slice(cursor).Span));
            var pskMode = Assert.Single(pskModes);
            Assert.Equal(PskKeyExchangeMode.PskDheKe, pskMode);
            var supportedVersion = Assert.Single(supportedVersions);
            Assert.Equal(ProtocolVersion.Tls13, supportedVersion);
        }

        private string GetMessageHexString()
        {
            return "16030100ca010000c60303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000770000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d00170018000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b0003020304";
        }

        private byte[] GetBytesOfRandom()
        {
            return Utils.ParseHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        }

        private byte[] GetBytesOfSessionId()
        {
            return Utils.ParseHexString("20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        }

        private byte[] GetBytesOfPublicKey()
        {
            return Utils.ParseHexString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254");
        }
    }
}
