import 'dart:async';

import 'package:mubrambl/brambldart.dart';

abstract class AbstractTransactionUpdateFetcher {
  final StreamController<TransactionReceipt?>
      _transactionUpdateStreamController;

  AbstractTransactionUpdateFetcher()
      : _transactionUpdateStreamController = StreamController();

  /// Add [transaction] to the stream
  void emitTransactionUpdate(TransactionReceipt? transaction) =>
      _transactionUpdateStreamController.add(transaction);

  /// When [transaction] is added to stream
  Stream<TransactionReceipt?> onUpdate() =>
      _transactionUpdateStreamController.stream;

  /// Starts fetching transactionUpdates
  Future<void> start();

  /// Stops fetching transaction updates
  Future<void> stop();
}
