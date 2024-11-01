import 'package:plasma_protobuf/plasma_protobuf.dart';
import 'package:plasma_sdk/plasma_sdk.dart';
import 'package:plasma_service_kit/toolkit/features/simple_transaction/simple_transaction_algebra.dart';

export 'simple_transaction_algebra.dart';
export 'simple_transaction_algebra_error.dart';

class SimpleTransaction {
  SimpleTransaction({
    required this.walletStateAlgebra,
    required this.simpleTransactionAlgebra,
  });

  final WalletStateAlgebra walletStateAlgebra;
  final SimpleTransactionAlgebra simpleTransactionAlgebra;

  Future<Either<String, String>> createSimpleTransactionFromParams({
    required String keyfile,
    required String password,
    required (String, String, int?) fromCoordinates,
    required (String?, String?, int?) changeCoordinates,
    LockAddress? someToAddress,
    String? someToFellowship,
    String? someToTemplate,
    required int amount,
    required int fee,
    required ValueTypeIdentifier tokenType,
    Option<GroupId>? groupId,
    Option<SeriesId>? seriesId,
  }) async {
    try {
      final fromFellowship = fromCoordinates.$1;
      final fromTemplate = fromCoordinates.$2;
      final someFromState = fromCoordinates.$3;
      final someChangeFellowship = changeCoordinates.$1;
      final someChangeTemplate = changeCoordinates.$2;
      final someChangeState = changeCoordinates.$3;

      walletStateAlgebra.validateCurrentIndicesForFunds(
          fromFellowship, fromTemplate, someFromState);

      final res =
          await simpleTransactionAlgebra.createSimpleTransactionFromParams(
        keyfile: keyfile,
        password: password,
        fromFellowship: fromFellowship,
        fromTemplate: fromTemplate,
        someFromState: someFromState,
        someChangeFellowship: someChangeFellowship,
        someChangeTemplate: someChangeTemplate,
        someChangeState: someChangeState,
        someToAddress: someToAddress,
        someToFellowship: someToFellowship,
        someToTemplate: someToTemplate,
        amount: amount,
        fee: fee,
        tokenType: tokenType,
      );

      return res.fold((p0) => Either.left(p0.description),
          (_) => Either.right("Transaction successfully created"));
    } catch (e) {
      return Either.left('Unexpected error: $e');
    }
  }
}
