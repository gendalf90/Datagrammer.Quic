using Datagrammer.Quic.Protocol;
using Datagrammer.Quic.Protocol.Packet;
using Datagrammer.Quic.Protocol.Packet.Frame;
using Datagrammer.Quic.Protocol.Tls;
using System;
using Xunit;

namespace Tests.Packet
{
    public class InitialClientHelloTests
    {
        [Fact]
        public void Write_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetMessageHex();
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var version = PacketVersion.CreateByDraft(32);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var clientHelloBytes = Utils.ParseHexString(GetTlsClientHelloHex());

            //Act
            var cursor = new MemoryCursor(buffer);

            using (InitialPacket.StartWriting(cursor, version, destConnectionId, sourceConnectionId, packetNumber, token))
            {
                using (PaddingFrame.EnsureLength(cursor, 1162))
                {
                    using (CryptoFrame.StartWriting(cursor, 0))
                    {
                        clientHelloBytes.CopyTo(cursor);
                    }
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Write_Encrypted_ResultBytesAreExpected()
        {
            //Arrange
            var expectedBytes = GetProtectedMessageHex();
            var buffer = new byte[PacketBuffer.MaxPacketSize];
            var version = PacketVersion.CreateByDraft(32);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var clientHelloBytes = Utils.ParseHexString(GetTlsClientHelloHex());
            var secrets = GetSecrets();
            var aead = Cipher.TLS_AES_128_GCM_SHA256.CreateAead(Utils.ParseHexString(secrets.Iv), Utils.ParseHexString(secrets.Key));
            var cipher = Cipher.TLS_AES_128_GCM_SHA256.CreateCipher(Utils.ParseHexString(secrets.Hp));

            //Act
            var cursor = new MemoryCursor(buffer);

            using (InitialPacket.StartProtectedWriting(aead, cipher, cursor, version, destConnectionId, sourceConnectionId, packetNumber, token))
            {
                using (PaddingFrame.EnsureLength(cursor, 1162))
                {
                    using (CryptoFrame.StartWriting(cursor, 0))
                    {
                        clientHelloBytes.CopyTo(cursor);
                    }
                }
            }

            //Assert
            Assert.Equal(expectedBytes, Utils.ToHexString(cursor.PeekStart().ToArray()), true);
        }

        [Fact]
        public void Read_ResultsAreExpected()
        {
            //Arrange
            var messageBytes = Utils.ParseHexString(GetMessageHex());
            var version = PacketVersion.CreateByDraft(32);
            var connectionIds = GetConnectionIdsHex();
            var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
            var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
            var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
            var token = PacketToken.Empty;
            var clientHelloBytes = GetTlsClientHelloHex();
            var cryptoFrame = new CryptoFrame();
            var paddingFrameCount = 0;

            //Act
            var cursor = new MemoryCursor(messageBytes);
            var result = InitialPacket.TryParse(cursor, out var packet);

            using (packet.Payload.SetCursor(cursor))
            {
                result &= CryptoFrame.TryParse(cursor, out cryptoFrame);

                paddingFrameCount = PaddingFrame.SkipRange(cursor);

                result &= cursor.IsEnd();
            }

            result &= cursor.IsEnd();

            //Assert
            Assert.True(result);
            Assert.Equal(917, paddingFrameCount);
            Assert.Equal(version, packet.Version);
            Assert.Equal(sourceConnectionId, packet.SourceConnectionId);
            Assert.Equal(destConnectionId, packet.DestinationConnectionId);
            Assert.Equal(packetNumber, packet.Number);
            Assert.Equal(token, packet.Token);
            Assert.Equal(0, cryptoFrame.Offset);
            Assert.Equal(clientHelloBytes, Utils.ToHexString(cryptoFrame.Data.Read(cursor).ToArray()), true);
        }

        //[Fact]
        //public void Read_Protected_ResultsAreExpected()
        //{
        //    //Arrange
        //    var messageBytes = Utils.ParseHexString(GetMessageHex());
        //    var version = PacketVersion.CreateByDraft(32);
        //    var connectionIds = GetConnectionIdsHex();
        //    var sourceConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.SourceConnectionIdHex));
        //    var destConnectionId = PacketConnectionId.Parse(Utils.ParseHexString(connectionIds.DestConnectionIdHex));
        //    var packetNumber = PacketNumber.Parse(Utils.ParseHexString(GetPacketNumberHex()));
        //    var token = PacketToken.Empty;
        //    var clientHelloBytes = GetTlsClientHelloHex();
        //    var cryptoFrame = new CryptoFrame();
        //    var paddingFrameCount = 0;

        //    //Act
        //    var cursor = new MemoryCursor(messageBytes);
        //    var result = InitialPacket.TryParse(cursor, out var packet);

        //    using (packet.Payload.SetCursor(cursor))
        //    {
        //        result &= CryptoFrame.TryParse(cursor, out cryptoFrame);

        //        paddingFrameCount = PaddingFrame.SkipRange(cursor);

        //        result &= cursor.IsEnd();
        //    }

        //    result &= cursor.IsEnd();

        //    //Assert
        //    Assert.True(result);
        //    Assert.Equal(917, paddingFrameCount);
        //    Assert.Equal(version, packet.Version);
        //    Assert.Equal(sourceConnectionId, packet.SourceConnectionId);
        //    Assert.Equal(destConnectionId, packet.DestinationConnectionId);
        //    Assert.Equal(packetNumber, packet.Number);
        //    Assert.Equal(token, packet.Token);
        //    Assert.Equal(0, cryptoFrame.Offset);
        //    Assert.Equal(clientHelloBytes, Utils.ToHexString(cryptoFrame.Data.Read(cursor).ToArray()), true);
        //}

        private string GetMessageHex()
        {
            return "c3ff000020088394c8f03e5157080000449e00000002060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001ffa500320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        }

        private (string DestConnectionIdHex, string SourceConnectionIdHex) GetConnectionIdsHex()
        {
            return ("088394c8f03e515708", "00");
        }

        private (string Key, string Iv, string Hp) GetSecrets()
        {
            return ("175257a31eb09dea9366d8bb79ad80ba", "6b26114b9cba2b63a9e8dd4f", "9ddd12c994c0698b89374a9c077a3077");
        }

        private string GetPacketNumberHex()
        {
            return "00000002";
        }

        private string GetProtectedMessageHex()
        {
            return "cdff000020088394c8f03e5157080000449e9cdb990bfb66bc6a93032b50dd8973972d149421874d3849e3708d71354ea33bcdc356f3ea6e2a1a1bd7c3d140038d3e784d04c30a2cdb40c32523aba2dafe1c1bf3d27a6be38fe38ae033fbb0713c1c73661bb6639795b42b97f77068ead51f11fbf9489af2501d09481e6c64d4b8551cd3cea70d830ce2aeeec789ef551a7fbe36b3f7e1549a9f8d8e153b3fac3fb7b7812c9ed7c20b4be190ebd8995626e7f0fc887925ec6f0606c5d36aa81bebb7aacdc4a31bb5f23d55faef5c51905783384f375a43235b5c742c78ab1bae0a188b75efbde6b3774ed61282f9670a9dea19e1566103ce675ab4e21081fb5860340a1e88e4f10e39eae25cd685b10929636d4f02e7fad2a5a458249f5c0298a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d07bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b88fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce551986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f76d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef43045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe231da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d44456269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf36b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a5668c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d48b5a464ca5b62df3be35ee0d0a2ec68f3";
        }

        private string GetTlsClientHelloHex()
        {
            return "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001ffa500320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff";
        }
    }
}
