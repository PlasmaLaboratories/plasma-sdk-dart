import 'package:meta/meta.dart';
import 'package:plasma_protobuf/plasma_protobuf.dart';

import '../../crypto/encryption/cipher/aes.dart';
import '../../crypto/encryption/kdf/scrypt.dart';
import '../../crypto/encryption/mac.dart';
import '../../crypto/generation/bip32_index.dart';
import '../../crypto/generation/key_initializer/extended_ed25519_initializer.dart';
import '../../crypto/generation/mnemonic/entropy.dart';
import '../../crypto/generation/mnemonic/mnemonic.dart';
import '../../crypto/signing/extended_ed25519/extended_ed25519.dart';
import '../../crypto/signing/extended_ed25519/extended_ed25519_spec.dart' as x_spec;
import '../../utils/extensions.dart';
import '../data_api/wallet_key_api_algebra.dart';
import '../utils/proto_converters.dart';

/// Defines a Wallet API.
/// A Wallet is responsible for managing the user's keys
sealed class WalletApiDefinition {
  static const defaultName = "default";

  /// Saves a wallet.
  ///
  /// [vaultStore] - The [VaultStore] of the wallet to save.
  /// [name] - A name used to identify a wallet. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Throws [WalletApiFailure] if saving the wallet fails.
  Future<void> saveWallet(VaultStore vaultStore, {String name = defaultName});

  /// Saves a mnemonic.
  ///
  /// [mnemonic] - The mnemonic to save.
  /// [mnemonicName] - A name used to identify the mnemonic. Defaults to "mnemonic".
  ///
  /// Throws [WalletApiFailure] if saving the mnemonic fails.
  Future<void> saveMnemonic(List<String> mnemonic, {String mnemonicName = 'mnemonic'});

  /// Loads a wallet.
  ///
  /// [name] - A name used to identify a wallet. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Throws [WalletApiFailure] if loading the wallet fails.
  Future<VaultStore> loadWallet({String name = defaultName});

  /// Updates a wallet.
  ///
  /// [newWallet] - The new [VaultStore] of the wallet.
  /// [name] - A name used to identify a wallet. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Throws [WalletApiFailure] if updating the wallet fails.
  Future<void> updateWallet(VaultStore newWallet, {String name = defaultName});

  /// Deletes a wallet.
  ///
  /// [name] - A name used to identify the wallet. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Throws [WalletApiFailure] if deleting the wallet fails.
  Future<void> deleteWallet({String name = defaultName});

  /// Builds a [VaultStore] for the wallet from a main key encrypted with a password.
  ///
  /// [mainKey] - The main key to use to generate the wallet.
  /// [password] - The password to encrypt the wallet with.
  ///
  /// Returns the [VaultStore] of the newly created wallet, if successful. Else an error.
  VaultStore buildMainKeyVaultStore(List<int> mainKey, List<int> password);

  /// Creates a new wallet.
  ///
  /// [password] - The password to encrypt the wallet with.
  /// [passphrase] - The passphrase to use to generate the main key from the mnemonic. Defaults to `null`.
  /// [mLen] - The length of the mnemonic to generate. Defaults to `MnemonicSize.words12`.
  ///
  /// returns a [NewWalletResult] or throws [WalletApiFailure] if unsuccessful
  Future<NewWalletResult> createNewWallet(List<int> password,
      {String? passphrase, MnemonicSize mLen = const MnemonicSize.words12()});

  /// Creates a new wallet and then saves it.
  ///
  /// [password] - The password to encrypt the wallet with.
  /// [passphrase] - The passphrase to use to generate the main key from the mnemonic. Defaults to `null`.
  /// [mLen] - The length of the mnemonic to generate. Defaults to `MnemonicSize.words12`.
  /// [name] - A name used to identify a wallet. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  /// [mnemonicName] - A name used to identify the mnemonic. Defaults to "mnemonic".
  ///
  /// returns [NewWalletResult] or throws a [WalletApiFailure]
  Future<NewWalletResult> createAndSaveNewWallet(List<int> password,
      {String? passphrase,
      MnemonicSize mLen = const MnemonicSize.words12(),
      String name = 'default',
      String mnemonicName = 'mnemonic'}) async {
    try {
      final walletRes = await createNewWallet(password, passphrase: passphrase, mLen: mLen);
      await saveWallet(walletRes.mainKeyVaultStore, name: name);
      await saveMnemonic(walletRes.mnemonic, mnemonicName: mnemonicName);
      return walletRes;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failureDefault(context: e.toString());
    }
  }

  /// Extracts the Main Key Pair from a wallet.
  ///
  /// [vaultStore] - The [VaultStore] of the wallet to extract the keys from.
  /// [password] - The password to decrypt the wallet with.
  ///
  /// Throws [WalletApiFailure] if extracting the main key pair fails.
  KeyPair extractMainKey(VaultStore vaultStore, List<int> password);

  /// Derives a child key pair from a Main Key Pair.
  ///
  /// [keyPair] - The Main Key Pair to derive the child key pair from.
  /// [idx] - The path indices of the child key pair to derive.
  ///
  /// Returns the [KeyPair] of the derived child key pair, if successful. Else an error.
  KeyPair deriveChildKeys(KeyPair keyPair, Indices idx);

  /// Derives a child key pair from a Main Key Pair from a partial path (x and y).
  ///
  /// [keyPair] - The Main Key Pair to derive the child key pair from.
  /// [xFellowship] - The first path index of the child key pair to derive. Represents the fellowship index.
  /// [yTemplate] - The second path index of the child key pair to derive. Represents the template index.
  ///
  /// Returns the protobuf encoded keys of the child key pair.
  KeyPair deriveChildKeysPartial(KeyPair keyPair, int xFellowship, int yTemplate);

  /// Derives a child verification key pair one step down from a parent verification key. Note that this is a Soft
  /// Derivation.
  ///
  /// [vk] - The verification to derive the child key pair from.
  /// [idx] - The index to perform soft derivation in order to derive the child verification.
  ///
  /// Returns the protobuf child verification key.
  VerificationKey deriveChildVerificationKey(VerificationKey vk, int idx);

  /// Load a wallet and then extract the main key pair.
  ///
  /// [password] - The password to decrypt the wallet with.
  /// [name] - A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Throw [WalletApiFailure] if unsuccessful
  Future<KeyPair> loadAndExtractMainKey(List<int> password, {String name = defaultName}) async {
    try {
      final walletRes = await loadWallet(name: name);
      final keyPair = extractMainKey(walletRes, password);
      return keyPair;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failureDefault(context: e.toString());
    }
  }

  /// Update the password of a wallet.
  ///
  /// [oldPassword] - The old password of the wallet.
  /// [newPassword] - The new password to encrypt the wallet with.
  /// [name] - A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Returns the wallet's new [VaultStore] if creation and save was successful.
  /// Throws [WalletApiFailure] if unsuccessful.
  Future<VaultStore> updateWalletPassword(List<int> oldPassword, List<int> newPassword,
      {String name = defaultName}) async {
    try {
      final oldWallet = await loadWallet(name: name);
      final mainKey = extractMainKey(oldWallet, oldPassword);
      final newWallet = buildMainKeyVaultStore(mainKey.writeToBuffer(), newPassword);
      await updateWallet(newWallet, name: name);
      return newWallet;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failureDefault(context: e.toString());
    }
  }

  /// Import a wallet from a mnemonic.
  ///
  /// This method does not persist the imported wallet. It simply generates and returns the [VaultStore]
  /// corresponding to the mnemonic. See [importWalletAndSave].
  ///
  /// [mnemonic] - The mnemonic to import.
  /// [password] - The password to encrypt the wallet with.
  /// [passphrase] - The passphrase to use to generate the main key from the mnemonic.
  ///
  /// Returns the wallet's [VaultStore] if import and save was successful.
  /// Throws [WalletApiFailure] if unsuccessful.
  Future<VaultStore> importWallet(List<String> mnemonic, List<int> password, {String? passphrase});

  /// Import a wallet from a mnemonic and save it.
  ///
  /// [mnemonic] - The mnemonic to import.
  /// [password] - The password to encrypt the wallet with.
  /// [passphrase] - The passphrase to use to generate the main key from the mnemonic.
  /// [name] - A name used to identify a wallet in the DataApi. Defaults to "default". Most commonly, only one
  ///          wallet identity will be used. It is the responsibility of the dApp to keep track of the names of
  ///          the wallet identities if multiple will be used.
  ///
  /// Returns the wallet's [VaultStore] if import and save was successful.
  /// Throws [WalletApiFailure] if unsuccessful.
  Future<VaultStore> importWalletAndSave(List<String> mnemonic, List<int> password,
      {String? passphrase, String name = defaultName}) async {
    try {
      final walletRes = await importWallet(mnemonic, password, passphrase: passphrase);
      await saveWallet(walletRes, name: name);
      return walletRes;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failureDefault(context: e.toString());
    }
  }
}

class WalletApi extends WalletApiDefinition {
  /// Create an instance of the WalletAPI.
  ///
  /// The wallet uses ExtendedEd25519 to generate the main secret key.
  /// The wallet uses SCrypt as the KDF.
  /// The wallet uses AES as the cipher.
  ///
  /// [walletKeyApi] The Api to use to handle wallet key persistence.
  /// [extendedEd25519Instance] The instance of ExtendedEd25519 to use.
  /// [kdfInstance] The instance of SCrypt to use. This should be overridden in cases where the default SCrypt parameters are not desired.
  /// Returns a new WalletAPI instance.
  WalletApi(
    this.walletKeyApi, {
    ExtendedEd25519? extendedEd25519Instance,
    SCrypt? kdfInstance,
  }) {
    instance = extendedEd25519Instance ?? ExtendedEd25519();
    kdf = kdfInstance ?? SCrypt.withGeneratedSalt();
  }
  late final ExtendedEd25519 instance;

  final purpose = 1852;
  final coinType = 7091;

  late final SCrypt kdf;
  final cipher = Aes(); // generates IV
  final WalletKeyApiAlgebra walletKeyApi;

  @override
  KeyPair extractMainKey(VaultStore vaultStore, List<int> password) {
    try {
      final decoded = VaultStore.decodeCipher(vaultStore, password.toUint8List())
          .getOrThrow(exception: WalletApiFailure.failedToDecodeWallet());
      final keypair = KeyPair.fromBuffer(decoded);
      return keypair;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failureDefault(context: e.toString());
    }
  }

  @override
  KeyPair deriveChildKeys(KeyPair keyPair, Indices idx) {
    assert(keyPair.sk.hasExtendedEd25519(), "keyPair must be an extended Ed25519 key");
    assert(keyPair.vk.hasExtendedEd25519(), "keyPair must be an extended Ed25519 key");

    final xCoordinate = HardenedIndex(idx.x);
    final yCoordinate = SoftIndex(idx.y);
    final zCoordinate = SoftIndex(idx.z);

    final sk = x_spec.SecretKey.proto(keyPair.sk.extendedEd25519);
    final kp = instance.deriveKeyPairFromChildPath(sk, [xCoordinate, yCoordinate, zCoordinate]);
    return ProtoConverters.keyPairToProto(kp);
  }

  @override
  KeyPair deriveChildKeysPartial(KeyPair keyPair, int xFellowship, int yTemplate) {
    assert(keyPair.sk.hasExtendedEd25519(), "keyPair must be an extended Ed25519 key");
    assert(keyPair.vk.hasExtendedEd25519(), "keyPair must be an extended Ed25519 key");

    final xCoordinate = HardenedIndex(xFellowship);
    final yCoordinate = SoftIndex(yTemplate);

    final sk = x_spec.SecretKey.proto(keyPair.sk.extendedEd25519);
    final kp = instance.deriveKeyPairFromChildPath(sk, [xCoordinate, yCoordinate]);
    return ProtoConverters.keyPairToProto(kp);
  }

  @override
  VerificationKey deriveChildVerificationKey(VerificationKey vk, int idx) {
    assert(vk.hasExtendedEd25519(), "verification key must be an extended Ed25519 key");

    final pk = instance.deriveChildVerificationKey(x_spec.PublicKey.proto(vk.extendedEd25519), SoftIndex(idx));
    return ProtoConverters.publicKeyToProto(pk);
  }

  @override
  Future<NewWalletResult> createNewWallet(List<int> password,
      {String? passphrase, MnemonicSize mLen = const MnemonicSize.words12()}) async {
    try {
      final entropy = Entropy.generate(size: mLen);
      final mainkey = entropyToMainKey(entropy, passphrase: passphrase).writeToBuffer();
      final vaultStore = buildMainKeyVaultStore(mainkey, password);
      final mnemonic =
          (await Entropy.toMnemonicString(entropy)).getOrThrow(exception: WalletApiFailure.failedToInitializeWallet());
      return NewWalletResult(mnemonic: mnemonic, mainKeyVaultStore: vaultStore);
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failedToInitializeWallet(context: e.toString());
    }
  }

  @override
  Future<VaultStore> importWallet(List<String> mnemonic, List<int> password, {String? passphrase}) async {
    try {
      final entropy = (await Entropy.fromMnemonicString(mnemonic.join(" ")))
          .getOrThrow(exception: WalletApiFailure.failedToInitializeWallet());
      final mainKey = entropyToMainKey(entropy, passphrase: passphrase).writeToBuffer();
      final vaultStore = buildMainKeyVaultStore(mainKey, password);
      return vaultStore;
    } on WalletApiFailure {
      rethrow;
    } catch (e) {
      throw WalletApiFailure.failedToInitializeWallet(context: e.toString());
    }
  }

  @override
  Future<void> saveWallet(VaultStore vaultStore, {String name = WalletApiDefinition.defaultName}) async {
    try {
      await walletKeyApi.saveMainKeyVaultStore(vaultStore, name);
    } catch (e) {
      throw WalletApiFailure.failedToSaveWallet(context: e.toString());
    }
  }

  @override
  Future<void> saveMnemonic(List<String> mnemonic, {String mnemonicName = 'mnemonic'}) async {
    try {
      await walletKeyApi.saveMnemonic(mnemonic, mnemonicName);
    } catch (e) {
      throw WalletApiFailure.failedToSaveMnemonic(context: e.toString());
    }
  }

  @override
  Future<VaultStore> loadWallet({String name = WalletApiDefinition.defaultName}) async {
    try {
      return await walletKeyApi.getMainKeyVaultStore(name);
    } catch (e) {
      throw WalletApiFailure.failedToLoadWallet(context: e.toString());
    }
  }

  @override
  Future<void> updateWallet(VaultStore newWallet, {String name = WalletApiDefinition.defaultName}) async {
    try {
      await walletKeyApi.updateMainKeyVaultStore(newWallet, name);
    } catch (e) {
      throw WalletApiFailure.failedToUpdateWallet(context: e.toString());
    }
  }

  @override
  Future<void> deleteWallet({String name = WalletApiDefinition.defaultName}) async {
    try {
      await walletKeyApi.deleteMainKeyVaultStore(name);
    } catch (e) {
      throw WalletApiFailure.failedToDeleteWallet(context: e.toString());
    }
  }

  @override
  VaultStore buildMainKeyVaultStore(List<int> mainKey, List<int> password) {
    final derivedKey = kdf.deriveKey(password.toUint8List());
    final cipherText = cipher.encrypt(mainKey.toUint8List(), derivedKey);
    final mac = Mac(derivedKey, cipherText).value;
    return VaultStore(kdf, cipher, cipherText, mac);
  }

  KeyPair entropyToMainKey(Entropy entropy, {String? passphrase}) {
    final rootKey = ExtendedEd25519Intializer(instance).fromEntropy(entropy, password: passphrase);
    final p = HardenedIndex(purpose); // following CIP-1852
    final c = HardenedIndex(coinType); // Topl coin type registered with SLIP-0044
    return ProtoConverters.keyPairToProto(instance.deriveKeyPairFromChildPath(rootKey as x_spec.SecretKey, [p, c]));
  }
}

class NewWalletResult {
  NewWalletResult({required this.mnemonic, required this.mainKeyVaultStore});
  final List<String> mnemonic;
  final VaultStore mainKeyVaultStore;

  NewWalletResult copyWith({List<String>? mnemonic, VaultStore? mainKeyVaultStore}) {
    return NewWalletResult(
      mnemonic: mnemonic ?? this.mnemonic,
      mainKeyVaultStore: mainKeyVaultStore ?? this.mainKeyVaultStore,
    );
  }
}

@immutable
class WalletApiFailure implements Exception {
  const WalletApiFailure(this.type, this.message);

  factory WalletApiFailure.failedToInitializeWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToInitializeWallet, context);
  factory WalletApiFailure.failedToSaveWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToSaveWallet, context);
  factory WalletApiFailure.failedToSaveMnemonic({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToSaveMnemonic, context);
  factory WalletApiFailure.failedToLoadWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToLoadWallet, context);
  factory WalletApiFailure.failedToUpdateWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToUpdateWallet, context);
  factory WalletApiFailure.failedToDeleteWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToDeleteWallet, context);
  factory WalletApiFailure.failedToDecodeWallet({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failedToDecodeWallet, context);
  factory WalletApiFailure.failureDefault({String? context}) =>
      WalletApiFailure(WalletApiFailureType.failureDefault, context);
  final String? message;
  final WalletApiFailureType type;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is WalletApiFailure && runtimeType == other.runtimeType && type == other.type && message == other.message;

  @override
  int get hashCode => type.hashCode ^ message.hashCode;
}

enum WalletApiFailureType {
  failedToInitializeWallet,
  failedToSaveWallet,
  failedToSaveMnemonic,
  failedToLoadWallet,
  failedToUpdateWallet,
  failedToDeleteWallet,
  failedToDecodeWallet,
  failureDefault,
}
