use rand_core::OsRng;
use x25519_dalek::{
    StaticSecret, 
    PublicKey
};
use hkdf::Hkdf;
use sha2::Sha256;
use aes::cipher::{
    block_padding::Pkcs7, 
    BlockDecryptMut, 
    BlockEncryptMut, 
    KeyIvInit
};
use generic_array::{
    GenericArray,
    typenum::{U32, U16},
};

pub struct Bob {
    pub identity_key:     StaticSecret,
    pub signed_pre_key:   StaticSecret,
    pub one_time_pre_key: StaticSecret,
    pub root_ratchet:     SymmetricRatchet,
    pub recv_ratchet:     SymmetricRatchet,
    pub send_ratchet:     SymmetricRatchet,
    pub shared_secret:    Vec<u8>,
    pub dh_ratchet:       Option<StaticSecret>,
}

pub struct Alice {
    pub identity_key:  StaticSecret,
    pub ephemeral_key: StaticSecret,
    pub root_ratchet:  SymmetricRatchet,
    pub recv_ratchet:  SymmetricRatchet,
    pub send_ratchet:  SymmetricRatchet,
    pub shared_secret: Vec<u8>,
    pub dh_ratchet:    Option<StaticSecret>,
}

pub struct SymmetricRatchet {
    state: Vec<u8>,
}

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

impl SymmetricRatchet {

    pub fn new() -> Self {
        Self {
            state: Vec::new(),
        }
    }

    pub fn initialize(key: &[u8]) -> Self {
        Self {
            state: key.to_vec(),
        }
    }

    pub fn next(&mut self, input: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut value = self.state.clone();
        value.extend(input);
        let output = hkdf(&value, 80);
        self.state = output[..32].to_vec();
        (output[32..64].to_vec(), output[64..].to_vec())
    }
}

impl Bob {

    pub fn new() -> Self {
        Self {
            identity_key:     StaticSecret::random_from_rng(OsRng),
            signed_pre_key:   StaticSecret::random_from_rng(OsRng),
            one_time_pre_key: StaticSecret::random_from_rng(OsRng),
            dh_ratchet:       Some(StaticSecret::random_from_rng(OsRng)),
            root_ratchet:     SymmetricRatchet::new(),
            recv_ratchet:     SymmetricRatchet::new(),
            send_ratchet:     SymmetricRatchet::new(),
            shared_secret:    Vec::new(),
        }
    }

    pub fn x3dh(&mut self, alice: &Alice) {
        let dh1 = self.signed_pre_key.diffie_hellman(&PublicKey::from(&alice.identity_key)).as_bytes().to_vec();
        let dh2 = self.identity_key.diffie_hellman(&PublicKey::from(&alice.ephemeral_key)).as_bytes().to_vec();
        let dh3 = self.signed_pre_key.diffie_hellman(&PublicKey::from(&alice.ephemeral_key)).as_bytes().to_vec();
        let dh4 = self.one_time_pre_key.diffie_hellman(&PublicKey::from(&alice.ephemeral_key)).as_bytes().to_vec();

        let mut shared_secret = Vec::new();

        shared_secret.extend(dh1);
        shared_secret.extend(dh2);
        shared_secret.extend(dh3);
        shared_secret.extend(dh4);
        
        self.shared_secret = hkdf(&shared_secret, 32);
    }
    
    pub fn initialize_ratchets(&mut self) {
        self.root_ratchet = SymmetricRatchet::initialize(&self.shared_secret);
        self.recv_ratchet = SymmetricRatchet::initialize(&self.root_ratchet.next(Vec::new()).0);
        self.send_ratchet = SymmetricRatchet::initialize(&self.root_ratchet.next(Vec::new()).0);
    }

    pub fn dh_ratchet_recv(&mut self, alice_public: PublicKey) {
        let dh_recv = self.dh_ratchet.clone().unwrap().diffie_hellman(&alice_public);
        let shared_recv = self.root_ratchet.next(dh_recv.as_bytes().to_vec()).0;
        self.recv_ratchet = SymmetricRatchet::initialize(&shared_recv);
    }

    pub fn dh_ratchet_send(&mut self, alice_public: PublicKey) {
        self.dh_ratchet = Some(StaticSecret::random_from_rng(OsRng));
        let dh_send = self.dh_ratchet.clone().unwrap().diffie_hellman(&alice_public);
        let shared_send = self.root_ratchet.next(dh_send.as_bytes().to_vec()).0;
        self.send_ratchet = SymmetricRatchet::initialize(&shared_send);
    }

    pub fn send(&mut self, alice: &mut Alice, message: &[u8]) -> String {
        self.dh_ratchet_send(PublicKey::from(&alice.dh_ratchet.clone().unwrap()));
        let (key, iv) = self.send_ratchet.next(Vec::new());
        assert!(key.len() == 32, "Key must be exactly 32 bytes.");
        assert!(iv.len() == 16, "IV must be exactly 16 bytes.");
        let key = GenericArray::clone_from_slice(&key[..32]);
        let iv = GenericArray::clone_from_slice(&iv[..16]);
        let mut buffer = [0u8; 48];
        let ciphertext = Aes256CbcEnc::new(&key, &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(message, &mut buffer)
            .expect("Failed to encrypt plaintext");
        hex::encode(ciphertext)
    }

    pub fn recv(&mut self, ciphertext: &[u8], alice_public: PublicKey) -> String {
        self.dh_ratchet_recv(alice_public);
        let (key, iv) = self.recv_ratchet.next(Vec::new());
        assert!(key.len() == 32, "Key must be exactly 32 bytes.");
        assert!(iv.len() == 16, "IV must be exactly 16 bytes.");
        let key = GenericArray::clone_from_slice(&key[..32]);
        let iv = GenericArray::clone_from_slice(&iv[..16]);
        let mut buffer = [0u8; 48];
        let plaintext = Aes256CbcDec::new(&key, &iv)
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
            .expect("Failed to decrypt ciphertext");
        
        String::from_utf8(plaintext.to_vec()).unwrap()
    }

    pub fn get_public_key(&self, alice: &Alice) -> PublicKey {
        PublicKey::from(&alice.dh_ratchet.clone().unwrap())
    }
}

impl Alice {
    pub fn new() -> Self {
        Self {
            identity_key:  StaticSecret::random_from_rng(OsRng),
            ephemeral_key: StaticSecret::random_from_rng(OsRng),
            dh_ratchet:    None,
            root_ratchet:  SymmetricRatchet::new(),
            recv_ratchet:  SymmetricRatchet::new(),
            send_ratchet:  SymmetricRatchet::new(),
            shared_secret: Vec::new(),
        }
    }

    pub fn x3dh(&mut self, bob: &Bob) {
        let dh1 = self.identity_key.diffie_hellman(&PublicKey::from(&bob.signed_pre_key)).as_bytes().to_vec();
        let dh2 = self.ephemeral_key.diffie_hellman(&PublicKey::from(&bob.identity_key)).as_bytes().to_vec();
        let dh3 = self.ephemeral_key.diffie_hellman(&PublicKey::from(&bob.signed_pre_key)).as_bytes().to_vec();
        let dh4 = self.ephemeral_key.diffie_hellman(&PublicKey::from(&bob.one_time_pre_key)).as_bytes().to_vec();

        let mut shared_secret = Vec::new();

        shared_secret.extend(dh1);
        shared_secret.extend(dh2);
        shared_secret.extend(dh3);
        shared_secret.extend(dh4);

        self.shared_secret = hkdf(&shared_secret, 32);
    }

    pub fn initialize_ratchets(&mut self) {
        self.root_ratchet = SymmetricRatchet::initialize(&self.shared_secret);
        self.recv_ratchet = SymmetricRatchet::initialize(&self.root_ratchet.next(Vec::new()).0);
        self.send_ratchet = SymmetricRatchet::initialize(&self.root_ratchet.next(Vec::new()).0);
    }

    pub fn dh_ratchet_recv(&mut self, bob_public: PublicKey) {
        let dh_recv = self.dh_ratchet.clone().unwrap().diffie_hellman(&bob_public);
        let shared_recv = self.root_ratchet.next(dh_recv.as_bytes().to_vec()).0;
        self.recv_ratchet = SymmetricRatchet::initialize(&shared_recv);
    }

    pub fn dh_ratchet_send(&mut self, bob_public: PublicKey) {
        self.dh_ratchet = Some(StaticSecret::random_from_rng(OsRng));
        let dh_send = self.dh_ratchet.clone().unwrap().diffie_hellman(&bob_public);
        let shared_send = self.root_ratchet.next(dh_send.as_bytes().to_vec()).0;
        self.send_ratchet = SymmetricRatchet::initialize(&shared_send);
    }

    pub fn send(&mut self, bob: &mut Bob, message: &[u8]) -> String {
        self.dh_ratchet_send(PublicKey::from(&bob.dh_ratchet.clone().unwrap()));
        let (key, iv) = self.send_ratchet.next(Vec::new());
        assert!(key.len() == 32, "Key must be exactly 32 bytes.");
        assert!(iv.len() == 16, "IV must be exactly 16 bytes.");
        let key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&key[..32]);
        let iv: GenericArray<u8, U16> = GenericArray::clone_from_slice(&iv[..16]);
        let mut buffer = [0u8; 48];
        let ciphertext = Aes256CbcEnc::new(&key, &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(message, &mut buffer)
            .expect("Failed to encrypt plaintext");
        hex::encode(ciphertext)
    }

    pub fn recv(&mut self, ciphertext: &[u8], bob_public: PublicKey) -> String {
        self.dh_ratchet_recv(bob_public);
        let (key, iv) = self.recv_ratchet.next(Vec::new());
        assert!(key.len() == 32, "Key must be exactly 32 bytes.");
        assert!(iv.len() == 16, "IV must be exactly 16 bytes.");
        let key = GenericArray::clone_from_slice(&key[..32]);
        let iv = GenericArray::clone_from_slice(&iv[..16]);
        let mut buffer = [0u8; 48];
        let plaintext = Aes256CbcDec::new(&key, &iv)
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buffer)
            .expect("Failed to decrypt ciphertext");
        
        String::from_utf8(plaintext.to_vec()).unwrap()
    }

    pub fn get_public_key(&self, bob: &Bob) -> PublicKey {
        PublicKey::from(&bob.dh_ratchet.clone().unwrap())
    }
}

pub fn hkdf(input: &[u8], length: usize) -> Vec<u8> {
    let mut okm = vec![0u8; length];
    let hk = Hkdf::<Sha256>::from_prk(input).unwrap();
    hk.expand(&[], &mut okm).unwrap();
    okm.to_vec()
}


