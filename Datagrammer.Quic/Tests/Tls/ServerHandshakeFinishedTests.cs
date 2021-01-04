using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Tls;
using System;
using System.Collections.Generic;
using Xunit;
using TlsRecord = Datagrammer.Quic.Protocol.Tls.Record;

namespace Tests.Tls
{
    public class ServerHandshakeFinishedTests
    {
        [Fact]
        public void WriteEncryptedApplicationData_TLS_AES_128_GCM_SHA256_ResultIsExpected()
        {
            //Arrange
            var expectedData = GetEncryptedApplicationData();
            var cerificateData = GetCertificateData();
            var signatureData = GetSignatureData();
            var verifyData = GetVerifyData();
            var encryptionData = GetEncryptionData();
            var buffer = new byte[TlsBuffer.MaxRecordSize];

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(encryptionData.Iv), Utils.ParseHexString(encryptionData.Key));

            //Act
            var cursor = new MemoryCursor(buffer);

            using (TlsRecord.StartEncryptedWriting(cursor, RecordType.Handshake, aead, encryptionData.SeqNum))
            {
                EncryptedExtensions.WriteEmpty(cursor);

                using (Certificate.StartWriting(cursor))
                {
                    CertificateEntry.Write(Utils.ParseHexString(cerificateData), cursor);
                }

                using (CertificateVerify.StartWriting(cursor, SignatureScheme.RSA_PSS_RSAE_SHA256))
                {
                    Utils.ParseHexString(signatureData).CopyTo(cursor);
                }

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
            var cerificateData = GetCertificateData();
            var signatureData = GetSignatureData();
            var verifyData = GetVerifyData();
            var encryptionData = GetEncryptionData();
            var parsedCertificateEntries = new List<CertificateEntry>();
            var parsedSignatureData = new Memory<byte>();
            var parsedCertificateVerifyScheme = new SignatureScheme();
            var parsedVerifyData = new Memory<byte>();

            using var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(encryptionData.Iv), Utils.ParseHexString(encryptionData.Key));

            //Act
            var cursor = new MemoryCursor(Utils.ParseHexString(messageData));
            var result = TlsRecord.TryParseEncrypted(cursor, aead, encryptionData.SeqNum, out var record);

            using (record.Payload.SetCursor(cursor))
            {
                result &= EncryptedExtensions.TrySlice(cursor);

                result &= Certificate.TryParse(cursor, out var certificate);
                foreach (var entry in certificate.Payload.GetCertificateEntryReader(cursor))
                {
                    parsedCertificateEntries.Add(entry);
                }

                result &= CertificateVerify.TryParse(cursor, out var certificateVerify);
                parsedSignatureData = certificateVerify.Signature.AsMemory(cursor);
                parsedCertificateVerifyScheme = certificateVerify.Scheme;

                result &= Finished.TryParse(cursor, out var parsedVerifyDataBuffer);
                parsedVerifyData = parsedVerifyDataBuffer.AsMemory(cursor);

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(RecordType.Handshake, record.Type);
            Assert.Equal(ProtocolVersion.Tls12, record.ProtocolVersion);
            var certificateEntry = Assert.Single(parsedCertificateEntries);
            Assert.Equal(cerificateData, Utils.ToHexString(certificateEntry.Data.AsMemory(cursor).ToArray()), true);
            Assert.Equal(signatureData, Utils.ToHexString(parsedSignatureData.ToArray()), true);
            Assert.Equal(SignatureScheme.RSA_PSS_RSAE_SHA256, parsedCertificateVerifyScheme);
            Assert.Equal(verifyData, Utils.ToHexString(parsedVerifyData.ToArray()), true);
        }

        private string GetEncryptedApplicationData()
        {
            return "1703030475da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584ce08b0e455a350ae54d76349aa68c71ae";
        }

        private string GetCertificateData()
        {
            return "3082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a0";
        }

        private string GetSignatureData()
        {
            return "17feb533ca6d007d0058257968424bbc3aa6909e9d49557576a520e04a5ef05f0e86d24ff43f8eb861eef595228d7032aa360f714e667413926ef4f8b5803b69e35519e3b23f4373dfac6787066dcb4756b54560e0886e9b962c4ad28dab26bad1abc25916b09af286537f684f808aefee73046cb7df0a84fbb5967aca131f4b1cf389799403a30c02d29cbdadb72512db9cec2e5e1d00e50cafcf6f21091ebc4f253c5eab01a679baeabeedb9c9618f66006b8244d6622aaa56887ccfc66a0f3851dfa13a78cff7991e03cb2c3a0ed87d7367362eb7805b00b2524ff298a4da487cacdeaf8a2336c5631b3efa935bb411e753ca13b015fec7e4a730f1369f9e";
        }

        private string GetVerifyData()
        {
            return "ea6ee176dccc4af1859e9e4e93f797eac9a78ce439301e35275ad43f3cddbde3";
        }

        private (string Iv, string Key, int SeqNum) GetEncryptionData()
        {
            return ("4c042ddc120a38d1417fc815", "844780a7acad9f980fa25c114e43402a", 0);
        }
    }
}
