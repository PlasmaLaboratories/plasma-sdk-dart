// ignore_for_file: unused_local_variable

import 'dart:io';

import 'package:bip_topl/bip_topl.dart';
import 'package:docker_process/containers/cockroachdb.dart';
import 'package:http/http.dart';
import 'package:mubrambl/src/core/amount.dart';
import 'package:mubrambl/src/core/client.dart';
import 'package:mubrambl/src/credentials/credentials.dart';
import 'package:mubrambl/src/model/box/asset_code.dart';
import 'package:mubrambl/src/model/box/recipient.dart';
import 'package:mubrambl/src/model/box/security_root.dart';
import 'package:mubrambl/src/model/box/token_value_holder.dart';
import 'package:mubrambl/src/transaction/transactionReceipt.dart';
import 'package:mubrambl/src/utils/proposition_type.dart';
import 'package:mubrambl/src/utils/string_data_types.dart';
import 'package:pinenacl/encoding.dart';
import 'package:test/test.dart';

// import 'containers/bifrost.dart';
import 'test_api_key_auth.dart';

const _privateKey1 =
    '60d399da83ef80d8d4f8d223239efdc2b8fef387e1b5219137ffb4e8fbdea15adc9366b7d003af37c11396de9a83734e30e05e851efa32745c9cd7b42712c890608763770eddf77248ab652984b21b849760d1da74a6f5bd633ce41adceef07a';

const _privateKey2 =
    '70753be769a365f28d3ed8c4e573d43708a42970d90806fb9e8b2b502ce9a94c0e434fc8e9f88e31fc8b0bdd80223ac8fe37269597495ff0647d25659b90050d1c32ec2f4b5ae82493bcd9c63216c4fe8e69cdc339a0ab4ab80c3a8d8f9de6e3';

void main() async {
  late DockerProcess bifrost;
  late BramblClient client;

  late ToplSigningKey first;
  late ToplSigningKey second;

  setUpAll(() async {
    // print('Starting Bifrost on port 9085');

    // bifrost = await startBifrost(
    //     name: 'integrationTesting',
    //     version: '1.7.1',
    //     cleanup: true,
    //     imageName: 'toplprotocol/bifrost');
    // print('Waiting for Bifrost to start up');

    var connectionAttempts = 0;
    var successful = false;
    do {
      connectionAttempts++;
      try {
        await get(Uri.parse(
            'https://staging.vertx.topl.services/valhalla/$baasProjectId'));
        //await get(Uri.parse('http://localhost:9085'));
        successful = true;
      } on SocketException {
        await Future.delayed(const Duration(seconds: 2));
      }
    } while (connectionAttempts < 5);

    if (!successful) {
      throw StateError('Unable to connect to Bifrost Node');
    }
  });

  tearDownAll(() async {
    // await bifrost.stop();
    // await bifrost.kill();
  });

  setUp(() {
    client = BramblClient(
      basePathOverride:
          'https://staging.vertx.topl.services/valhalla/$baasProjectId',
      interceptors: [TestApiKeyAuthInterceptor()],
    );

    first = ToplSigningKey(
        Bip32SigningKey.decode(_privateKey1, coder: HexCoder.instance),
        0x10,
        PropositionType.ed25519());
    second = ToplSigningKey(
        Bip32SigningKey.decode(_privateKey2, coder: HexCoder.instance),
        0x10,
        PropositionType.ed25519());
  });

  group(BramblClient, () {
    test('test node info on private node', () async {
      try {
        final response = await client.getClientVersion();
        print(response);
      } catch (e) {
        print(e);
        fail('exception: $e');
      }
    });

    test('test node info on private node', () async {
      try {
        final response = await client.getNetwork();
        print(response);
      } catch (e) {
        print(e);
        fail('exception: $e');
      }
    });

    test('test block head info on private node', () async {
      try {
        final response = await client.getBlockNumber();
        print(response);
      } catch (e) {
        print(e);
        fail('exception: $e');
      }
    });

    test('Simple raw asset transaction', () async {
      final senderAddress = await first.extractAddress();
      final recipientAddress = await second.extractAddress();

      final balanceOfSender = await client.getBalance(senderAddress);
      print(balanceOfSender);
      final balanceOfRecipient = await client.getBalance(recipientAddress);
      print(balanceOfRecipient);
      final value = 1;

      final assetCode =
          AssetCode.initialize(1, senderAddress, 'testy', 'valhalla');

      final securityRoot = SecurityRoot.fromBase58(
          Base58Data.validated('11111111111111111111111111111111'));

      final assetValue =
          AssetValue(value.toString(), assetCode, securityRoot, 'metadata');

      final recipients = <String, AssetValue>{
        recipientAddress.toBase58(): assetValue
      };

      final fee = PolyAmount.fromUnitAndValue(PolyUnit.nanopoly, '100');

      final rawTransaction = await client.sendRawAssetTransfer(
          assetCode: assetCode,
          issuer: senderAddress,
          sender: senderAddress,
          recipients: recipients,
          fee: fee,
          minting: true,
          changeAddress: senderAddress,
          consolidationAddress: senderAddress);

      final to = AssetRecipient(recipientAddress, assetValue);

      expect(rawTransaction, isA<TransactionReceipt>());

      print(rawTransaction);
    });

    test('Simple raw poly transaction', () async {
      final senderAddress = await first.extractAddress();
      final recipientAddress = await second.extractAddress();

      final balanceOfSender = await client.getBalance(senderAddress);
      final balanceOfRecipient = await client.getBalance(recipientAddress);
      final value = 1;

      final polyValue = SimpleValue(value.toString());

      final recipients = <String, SimpleValue>{
        recipientAddress.toBase58(): polyValue
      };

      final fee = PolyAmount.fromUnitAndValue(PolyUnit.nanopoly, '100');

      final rawTransaction = await client.sendRawPolyTransfer(
          issuer: senderAddress,
          sender: senderAddress,
          recipients: recipients,
          fee: fee,
          changeAddress: senderAddress,
          data: Uint8List(0));

      final to = SimpleRecipient(recipientAddress, polyValue);

      expect(rawTransaction, isA<TransactionReceipt>());

      print(rawTransaction);
    });

    // test('Simple raw arbit transaction', () async {
    //   final senderAddress = await first.extractAddress();
    //   final recipientAddress = await second.extractAddress();

    //   final balanceOfSender = await client.getBalance(senderAddress);
    //   final balanceOfRecipient = await client.getBalance(recipientAddress);
    //   final value = 1;

    //   final arbitValue = SimpleValue(value.toString());

    //   final recipients = <String, SimpleValue>{
    //     recipientAddress.toBase58(): arbitValue
    //   };

    //   final fee = PolyAmount.fromUnitAndValue(PolyUnit.nanopoly, '100');

    //   final rawTransaction = await client.sendRawArbitTransfer(
    //       issuer: senderAddress,
    //       sender: senderAddress,
    //       recipients: recipients,
    //       fee: fee,
    //       changeAddress: senderAddress,
    //       consolidationAddress: senderAddress,
    //       data: Uint8List(0));

    //   final to = SimpleRecipient(recipientAddress, arbitValue);

    //   expect(rawTransaction, isA<TransactionReceipt>());

    //   print(rawTransaction);
    // });
  },
      skip: baasProjectId == '' || baasProjectId.length != 24
          ? 'Tests require a valid BaaS projectId'
          : null);
}
