import 'package:collection/collection.dart';
import 'package:protobuf/protobuf.dart';
import 'package:plasma_protobuf/plasma_protobuf.dart';
import 'package:plasma_sdk/src/sdk/validation/transaction_syntax_error.dart';
import 'package:plasma_sdk/src/sdk/validation/transaction_syntax_interpreter.dart';
import 'package:plasma_sdk/plasma_sdk.dart';
import 'package:test/test.dart';

import '../mock_helpers.dart';

void main() {
  group('TransactionSyntaxInterpreterTransferSeriesSpec', () {
    final txoAddress1 = TransactionOutputAddress(
        network: 1, ledger: 0, index: 0, id: dummyTxIdentifier);
    // final txoAddress2 = TransactionOutputAddress(network: 2, ledger: 0, index: 0, id: dummyTxIdentifier);

    test('Valid data-input case, transfer a simple series', () {
      final seriesPolicy = SeriesPolicy(
          label: 'seriesLabelB', registrationUtxo: txoAddress1);

      final v1In = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));
      final v1Out = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));

      final inputs = [
        SpentTransactionOutput(
            address: txoAddress1, attestation: attFull, value: v1In),
      ];

      final outputs = [
        UnspentTransactionOutput(address: trivialLockAddress, value: v1Out),
      ];

      final testTx = txFull.rebuild((p0) {
        p0.inputs.update(inputs);
        p0.outputs.update(outputs);
      });

      final result = TransactionSyntaxInterpreter.validate(testTx).swap();

      bool assertError = false;
      if (result.isRight) {
        result.get().map((e) {
          if (e.type == TransactionSyntaxErrorType.insufficientInputFunds) {
            final error = e as InsufficientInputFundsError;
            if (error.inputs
                    .equals(testTx.inputs.map((e) => e.value).toList()) &&
                error.outputs
                    .equals(testTx.outputs.map((e) => e.value).toList())) {
              assertError = true;
            }
          }
        });
      }

      expect(assertError, isFalse);
      expect(result.map((errors) => errors.length).getOrElse(0), equals(0));
    });

    test('Valid data-input case 2, transfer a simple series', () {
      final seriesPolicy = SeriesPolicy(
          label: 'seriesLabelB', registrationUtxo: txoAddress1);

      final v1In = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 2.toBytes)));
      final v1Out = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));
      final v2Out = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));

      final inputs = [
        SpentTransactionOutput(
            address: txoAddress1, attestation: attFull, value: v1In),
      ];

      final outputs = [
        UnspentTransactionOutput(address: trivialLockAddress, value: v1Out),
        UnspentTransactionOutput(address: trivialLockAddress, value: v2Out),
      ];

      final testTx = txFull.rebuild((p0) {
        p0.inputs.update(inputs);
        p0.outputs.update(outputs);
      });

      final result = TransactionSyntaxInterpreter.validate(testTx).swap();

      bool assertError = false;
      if (result.isRight) {
        result.get().map((e) {
          if (e.type == TransactionSyntaxErrorType.insufficientInputFunds) {
            final error = e as InsufficientInputFundsError;
            if (error.inputs
                    .equals(testTx.inputs.map((e) => e.value).toList()) &&
                error.outputs
                    .equals(testTx.outputs.map((e) => e.value).toList())) {
              assertError = true;
            }
          }
        });
      }

      expect(assertError, isFalse);
      expect(result.map((errors) => errors.length).getOrElse(0), equals(0));
    });

    test('InValid data-input case 2, transfer a simple series', () {
      final seriesPolicy = SeriesPolicy(
          label: 'seriesLabelB', registrationUtxo: txoAddress1);

      final v1In = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 3.toBytes)));
      final v1Out = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));
      final v2Out = Value(
          series: Value_Series(
              seriesId: seriesPolicy.computeId,
              quantity: Int128(value: 1.toBytes)));

      final inputs = [
        SpentTransactionOutput(
            address: txoAddress1, attestation: attFull, value: v1In),
      ];

      final outputs = [
        UnspentTransactionOutput(address: trivialLockAddress, value: v1Out),
        UnspentTransactionOutput(address: trivialLockAddress, value: v2Out),
      ];

      final testTx = txFull.rebuild((p0) {
        p0.inputs.update(inputs);
        p0.outputs.update(outputs);
      });

      final result = TransactionSyntaxInterpreter.validate(testTx).swap();

      // TODO(ultimaterex): Fix by implementing new validators in the [TransactionSyntaxInterpreter] specifically [assetEqualFundsValidation]
      bool assertError = false;
      if (result.isRight) {
        result.get().map((e) {
          if (e.type == TransactionSyntaxErrorType.insufficientInputFunds) {
            final error = e as InsufficientInputFundsError;
            if (error.inputs
                    .equals(testTx.inputs.map((e) => e.value).toList()) &&
                error.outputs
                    .equals(testTx.outputs.map((e) => e.value).toList())) {
              assertError = true;
            }
          }
        });
      }

      expect(assertError, isTrue);
      expect(result.map((errors) => errors.length).getOrElse(0), equals(1));
    });
  });
}
