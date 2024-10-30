import 'dart:convert';

import 'package:plasma_sdk/src/sdk/data_api/wallet_key_api_algebra.dart';

/// Mock implementation of the [WalletKeyApiAlgebra] interface.
class MockWalletKeyApi extends WalletKeyApiAlgebra {
  Map<String, String> mainKeyVaultStoreInstance = {};
  Map<String, List<String>> mnemonicInstance = {};

  static const defaultName = "default";

  @override
  Future<void> saveMainKeyVaultStore(VaultStore mainKeyVaultStore, String? name) async {
    final n = name ?? defaultName;
    if (n == 'error') {
      throw WalletKeyException.vaultStoreSave();
    } else {
      final json = jsonEncode(mainKeyVaultStore.toJson());
      mainKeyVaultStoreInstance[n] = json;
    }
  }

  @override
  Future<VaultStore> getMainKeyVaultStore(String? name) async {
    final n = name ?? defaultName;
    final json = mainKeyVaultStoreInstance[n];
    if (json == null) {
      throw WalletKeyException.vaultStoreNotInitialized();
    } else {
      return VaultStore.fromJson(jsonDecode(json))
          .toOption()
          .fold((p0) => p0, () => throw WalletKeyException.decodeVaultStore());
    }
  }

  @override
  Future<void> updateMainKeyVaultStore(VaultStore mainKeyVaultStore, String? name) async {
    final n = name ?? defaultName;
    final json = mainKeyVaultStoreInstance[n];
    if (json == null) {
      throw WalletKeyException.vaultStoreNotInitialized();
    } else {
      return saveMainKeyVaultStore(mainKeyVaultStore, name);
    }
  }

  @override
  Future<void> deleteMainKeyVaultStore(String? name) async {
    final n = name ?? defaultName;
    final json = mainKeyVaultStoreInstance[n];
    if (json == null) {
      throw WalletKeyException.vaultStoreDelete();
    } else {
      mainKeyVaultStoreInstance.remove(name);
    }
  }

  @override
  Future<void> saveMnemonic(
    List<String> mnemonic,
    String mnemonicName,
  ) async {
    mnemonicInstance[mnemonicName] = mnemonic;
  }
}
