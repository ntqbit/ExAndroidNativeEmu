import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.array import StringArray, ByteArray, Array
from androidemu.java.classes.enumeration import Enumeration
from androidemu.java.classes.exceptions import UnsupportedOperationException

logger = verboselogs.VerboseLogger(__name__)

KEYSTORES = {}

PURPOSE_ENCRYPT = 1 << 0
PURPOSE_DECRYPT = 1 << 1
PURPOSE_SIGN = 1 << 2
PURPOSE_VERIFY = 1 << 3
PURPOSE_WRAP_KEY = 1 << 5
PURPOSE_AGREE_KEY = 1 << 6
PURPOSE_ATTEST_KEY = 1 << 7

DIGEST_NONE = 'NONE'
DIGEST_MD5 = 'MD5'
DIGEST_SHA1 = 'SHA-1'
DIGEST_SHA224 = 'SHA-224'
DIGEST_SHA256 = 'SHA-256'
DIGEST_SHA384 = 'SHA-384'
DIGEST_SHA512 = 'SHA-512'

KEY_ALGORITHM_RSA = 'RSA'
KEY_ALGORITHM_EC = 'EC'
KEY_ALGORITHM_XDH = 'XDH'
KEY_ALGORITHM_AES = 'AES'


class KeyGenParameterSpec(metaclass=JavaClassDef, jvm_name='android/security/keystore/KeyGenParameterSpec'):
    def __init__(self, keystore_alias, purposes, alg_param_spec, digests, attestation_challenge):
        self._keystore_alias = keystore_alias
        self._purposes = purposes
        self._alg_param_spec = alg_param_spec
        self._digests = digests
        self._attestation_challenge = attestation_challenge


class KeyGenParameterSpec_Builder(metaclass=JavaClassDef, jvm_name='android/security/keystore/KeyGenParameterSpec$Builder'):
    def __init__(self):
        self._keystore_alias = None
        self._purposes = None
        self._alg_param_spec = None
        self._digests = None
        self._attestation_challenge = None

    @java_method_def('<init>', '(Ljava/lang/String;I)V', args_list=['jstring', 'jint'])
    def ctor(self, emu, keystore_alias: String, purposes: int):
        self._keystore_alias = keystore_alias.get_py_string()
        self._purposes = purposes

    @java_method_def('setAlgorithmParameterSpec',
                     '(Ljava/security/spec/AlgorithmParameterSpec;)Landroid/security/keystore/KeyGenParameterSpec$Builder;',
                     args_list=['jobject'])
    def setAlgorithmParameterSpec(self, emu, alg_param_spec):
        self._alg_param_spec = alg_param_spec
        return self

    @java_method_def('setDigests',
                     '([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;',
                     args_list=['jobject'])
    def setDigests(self, emu, digests: StringArray):
        self._digests = digests.get_py_items()
        return self

    @java_method_def('setAttestationChallenge',
                     '([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;',
                     args_list=['jobject'])
    def setAttestationChallenge(self, emu, attestation_challenge: ByteArray):
        self._attestation_challenge = attestation_challenge.get_py_items()
        return self

    @java_method_def('build', '()Landroid/security/keystore/KeyGenParameterSpec;')
    def build(self, emu):
        return KeyGenParameterSpec(self._keystore_alias,
                                   self._purposes,
                                   self._alg_param_spec,
                                   self._digests,
                                   self._attestation_challenge)


class ECGenParameterSpec(metaclass=JavaClassDef, jvm_name='java/security/spec/ECGenParameterSpec'):
    def __init__(self):
        self._stdName = None

    @java_method_def('<init>', '(Ljava/lang/String;)V', args_list=['jstring'])
    def ctor(self, emu, stdName):
        self._stdName = stdName


class PublicKey(metaclass=JavaClassDef, jvm_name='java/security/PublicKey'):
    def __init__(self):
        pass


class PrivateKey(metaclass=JavaClassDef, jvm_name='java/security/PrivateKey'):
    def __init__(self):
        pass


class KeyPair(metaclass=JavaClassDef, jvm_name='java/security/KeyPair'):
    def __init__(self, private_key, public_key):
        self._private_key = private_key
        self._public_key = public_key

    @java_method_def('getPrivate', '()Ljava/security/PrivateKey;')
    def getPrivate(self, emu):
        return self._private_key

    @java_method_def('getPublic', '()Ljava/security/PublicKey;')
    def getPublic(self, emu):
        return self._public_key


class KeyPairGenerator(metaclass=JavaClassDef, jvm_name='java/security/KeyPairGenerator'):
    def __init__(self, algorithm, provider):
        self._algorithm = algorithm
        self._provider = provider
        self._alg_param_spec = None

    @staticmethod
    @java_method_def('getInstance',
                     '(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;',
                     args_list=['jstring', 'jstring'])
    def getInstance(emu, algorithm: String, provider: String):
        return KeyPairGenerator(algorithm.get_py_string(), provider.get_py_string())

    @java_method_def('initialize', '(Ljava/security/spec/AlgorithmParameterSpec;)V', args_list=['jobject'])
    def initialize(self, emu, alg_param_spec):
        self._alg_param_spec = alg_param_spec

    @java_method_def('generateKeyPair', '()Ljava/security/KeyPair;')
    def generateKeyPair(self, emu):
        return KeyPair(PrivateKey(), PublicKey())


class KeyProperties(
        metaclass=JavaClassDef, jvm_name='android/security/keystore/KeyProperties',
        jvm_fields=[
            JavaFieldDef('PURPOSE_ENCRYPT', 'I', True, PURPOSE_ENCRYPT),
            JavaFieldDef('PURPOSE_DECRYPT', 'I', True, PURPOSE_DECRYPT),
            JavaFieldDef('PURPOSE_SIGN', 'I', True, PURPOSE_SIGN),
            JavaFieldDef('PURPOSE_VERIFY', 'I', True, PURPOSE_VERIFY),
            JavaFieldDef('PURPOSE_WRAP_KEY', 'I', True, PURPOSE_WRAP_KEY),
            JavaFieldDef('PURPOSE_AGREE_KEY', 'I', True, PURPOSE_AGREE_KEY),
            JavaFieldDef('PURPOSE_ATTEST_KEY', 'I', True, PURPOSE_ATTEST_KEY),

            JavaFieldDef('DIGEST_NONE', 'Ljava/lang/String;', True, String(DIGEST_NONE)),
            JavaFieldDef('DIGEST_MD5', 'Ljava/lang/String;', True, String(DIGEST_MD5)),
            JavaFieldDef('DIGEST_SHA1', 'Ljava/lang/String;', True, String(DIGEST_SHA1)),
            JavaFieldDef('DIGEST_SHA224', 'Ljava/lang/String;', True, String(DIGEST_SHA224)),
            JavaFieldDef('DIGEST_SHA256', 'Ljava/lang/String;', True, String(DIGEST_SHA256)),
            JavaFieldDef('DIGEST_SHA384', 'Ljava/lang/String;', True, String(DIGEST_SHA384)),
            JavaFieldDef('DIGEST_SHA512', 'Ljava/lang/String;', True, String(DIGEST_SHA512)),

            JavaFieldDef('KEY_ALGORITHM_RSA', 'Ljava/lang/String;', True, String(KEY_ALGORITHM_RSA)),
            JavaFieldDef('KEY_ALGORITHM_EC', 'Ljava/lang/String;', True, String(KEY_ALGORITHM_EC)),
            JavaFieldDef('KEY_ALGORITHM_XDH', 'Ljava/lang/String;', True, String(KEY_ALGORITHM_XDH)),
            JavaFieldDef('KEY_ALGORITHM_AES', 'Ljava/lang/String;', True, String(KEY_ALGORITHM_AES))
        ]):

    def __init__(self):
        pass


class KeyStore(metaclass=JavaClassDef, jvm_name='java/security/KeyStore'):
    def __init__(self, entries):
        self._entries = {}

    @java_method_def('getInstance', '(Ljava/lang/String;)Ljava/security/KeyStore;', args_list=['jstring'])
    @staticmethod
    def getInstance(emu, ks_type: String):
        ks_type_str = ks_type.get_py_string()
        logger.debug('KeyStore.getInstance: [type=%s]', ks_type_str)

        if ks_type_str not in KEYSTORES:
            KEYSTORES[ks_type_str] = KeyStore({})

        return KEYSTORES[ks_type_str]

    @java_method_def('load', '(Ljava/security/KeyStore$LoadStoreParameter;)V', args_list=['jobject'])
    def load(self, emu, load_store_parameter):
        pass

    @java_method_def('size', '()I', args_list=[])
    def size(self, emu):
        return len(self._entries)

    @java_method_def('aliases', '()Ljava/util/Enumeration;', args_list=[])
    def aliases(self, emu):
        return Enumeration(iter(map(String, self._entries.keys())))

    @java_method_def('containsAlias', '(Ljava/lang/String;)Z', args_list=['jstring'])
    def containsAlias(self, emu, alias_name: String):
        return alias_name.get_py_string() in self._entries

    @java_method_def('deleteEntry', '(Ljava/lang/String;)V', args_list=['jstring'])
    def deleteEntry(self, emu, alias: String):
        alias_pystr = alias.get_py_string()

        if alias_pystr in self._entries:
            del self._entries[alias_pystr]

    @java_method_def('getCertificateChain',
                     '(Ljava/lang/String;)[Ljava/security/cert/Certificate;',
                     args_list=['jstring'])
    def getCertificateChain(self, emu, alias: String):
        return emu.java_vm.throw(UnsupportedOperationException())
        return Array([])
