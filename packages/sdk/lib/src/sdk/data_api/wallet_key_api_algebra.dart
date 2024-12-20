import '../../crypto/encryption/vault_store.dart';

/// export crypto dependency to members
export 'package:plasma_sdk/src/crypto/encryption/vault_store.dart';

/// Defines a storage API for fetching and storing Topl Main Key Vault Store.
abstract class WalletKeyApiAlgebra {
  /// Persist a [VaultStore] for the Topl Main Secret Key.
  ///
  /// [mainKeyVaultStore] - The [VaultStore] to persist.
  /// [name] - The name identifier of the [VaultStore]. This is used to manage multiple wallet identities.
  /// Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
  /// to manage the names of the wallet identities if multiple will be used.
  ///
  /// Throws [WalletKeyException] if persisting fails due to an underlying cause.
  Future<void> saveMainKeyVaultStore(VaultStore mainKeyVaultStore, String name);

  /// Persist a mnemonic used to recover a Topl Main Secret Key.
  ///
  /// [mnemonic] - The mnemonic to persist.
  /// [mnemonicName] - The name identifier of the mnemonic.
  ///
  /// Throws [WalletKeyException] if persisting fails due to an underlying cause.
  Future<void> saveMnemonic(List<String> mnemonic, String mnemonicName);

  /// Return the ```VaultStore``` for the Topl Main Secret Key.
  ///
  /// [name] - The name identifier of the [VaultStore]. This is used to manage multiple wallet identities.
  /// Most commonly, only one wallet identity will be used. It is the responsibility of the dApp to manage
  /// the names of the wallet identities if multiple will be used.
  ///
  /// Throws [WalletKeyException] if retrieving fails due to an underlying cause.
  Future<VaultStore> getMainKeyVaultStore(String name);

  /// Update a persisted [VaultStore] for the Topl Main Secret Key.
  ///
  /// [mainKeyVaultStore] - The [VaultStore] to update.
  /// [name] - The name identifier of the [VaultStore] to update. This is used to manage multiple wallet identities.
  /// Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
  /// to manage the names of the wallet identities if multiple will be used.
  ///
  /// Throws [WalletKeyException] if the update fails due to an underlying cause (for example, does not exist).
  Future<void> updateMainKeyVaultStore(
      VaultStore mainKeyVaultStore, String name);

  /// Delete a persisted [VaultStore] for the Topl Main Secret Key.
  ///
  /// [name] - The name identifier of the [VaultStore] to delete. This is used to manage multiple wallet identities.
  /// Most commonly, only one wallet identity will be used. It is the responsibility of the dApp
  /// to manage the names of the wallet identities if multiple will be used.
  ///
  /// Throws [WalletKeyException] if the deletion fails due to an underlying cause (for example, does not exist).
  Future<void> deleteMainKeyVaultStore(String name);
}

/// TODO(ultimaterex): Source has moved this to MockWalletKeyApi, consider refactor
class WalletKeyException implements Exception {
  const WalletKeyException(this.type, this.message);

  factory WalletKeyException.decodeVaultStore({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.decodeVaultStoreException, context);
  factory WalletKeyException.vaultStoreDoesNotExist({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.vaultStoreDoesNotExistException, context);
  factory WalletKeyException.mnemonicDoesNotExist({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.mnemonicDoesNotExistException, context);

  factory WalletKeyException.vaultStoreSave({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.vaultStoreSaveException, context);
  factory WalletKeyException.vaultStoreInvalid({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.vaultStoreInvalidException, context);
  factory WalletKeyException.vaultStoreDelete({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.vaultStoreDeleteException, context);
  factory WalletKeyException.vaultStoreNotInitialized({String? context}) =>
      WalletKeyException(
          WalletKeyExceptionType.vaultStoreNotInitialized, context);
  final String? message;
  final WalletKeyExceptionType type;
}

enum WalletKeyExceptionType {
  decodeVaultStoreException,
  vaultStoreDoesNotExistException,
  mnemonicDoesNotExistException,

  vaultStoreSaveException,
  vaultStoreInvalidException,
  vaultStoreDeleteException,
  vaultStoreNotInitialized,
}
