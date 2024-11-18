import 'dart:typed_data';

import 'package:plasma_protobuf/plasma_protobuf.dart';
import 'package:plasma_sdk/plasma_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('TransactionCodecVectorsSpec', () {
    for (int i = 0; i < vectors.length; i++) {
      test("Vector $i", () {
        final vector = vectors[i];
        final txBytes = Encoding().decodeFromHex(vector.txHex).getOrThrow();
        final tx = IoTransaction.fromBuffer(txBytes)..freeze();
        final signable = ContainsSignable.ioTransaction(tx).signableBytes;
        final signableHex =
            Encoding().encodeToHex(Uint8List.fromList(signable.value));
        expect(signableHex, equals(vector.txSignableHex));
        expect(
            Encoding().encodeToBase58(Uint8List.fromList(tx.computeId.value)),
            equals(vector.txId));
      });
    }
  });
}

const vectors = [
  TestVector(
    txHex: "1a060a040a001200",
    txSignableHex: "0000",
    txId: "BhHbw2zXrJGgRW9YpKQV4c6sXfSwChXeYrRjW1aCQqRF",
  ),
  TestVector(
    txHex:
        "0a4f0a2b08d1041016180622220a202af1498060d30c7fa337ea54bd03905ff871c51bb658e14213992cab07825bd812150a130a110a0f0a0d220b0a03666f6f10b20318ff041a090a070a050a03325b7512360a2908d10410051a220a20ef52a274cb19813f68b826c34fe60ba7348f61d40fb279fb56df459b1ebd5ded12090a070a050a03214d7a1a170a150a0c08882710a8461885ccfba40112050a0336f42c",
    txSignableHex:
        "0002511606696f5f7472616e73616374696f6e5f33322af1498060d30c7fa337ea54bd03905ff871c51bb658e14213992cab07825bd800006865696768745f72616e6765666f6f01b2027f325b7500025105626f785f6c6f636b5f3332ef52a274cb19813f68b826c34fe60ba7348f61d40fb279fb56df459b1ebd5ded214d7a1388232836f42c",
    txId: "HroUqAw2X9eJPwgzsKJxMLAoJbCx27aVGsdVJFZNFMJH",
  ),
];

class TestVector {
  const TestVector(
      {required this.txHex, required this.txSignableHex, required this.txId});

  final String txHex;
  final String txSignableHex;
  final String txId;
}
