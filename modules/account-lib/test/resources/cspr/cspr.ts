import { KeyPair } from "../../../src/coin/cspr";

export const ACCOUNT_FROM_SEED = {
  seed: 'cd1eac3bc52716f3177bc7f9c5d7de10b98c74c6c1ace2c874e0e09f47469023',
  accountHash: 'f068b89fbd03587a1bedb79ead98d1c8f4c2f3181a6eddbc10ae98d0dd874e94',
  xPublicKey:
    'xpub661MyMwAqRbcEzDE55AJUGhMKJJ2nw1hnF1fBoaw2T47DQsJzhLXbygpggTXpkWPVENnzPYbgLRVPtmwjQQAiY9AbHX5Ys4KpLRuFtVNFtC',
  xPrivateKey:
    'xprv9s21ZrQH143K2W8ky3dJ78kcmGTYPUHrR264PRBKU7X8LcYATA2H4BNLqNDYi4mhSiJXRUAttHaJYBynN7iMU2vkJjEG4SK6xVJkymYUEyG',
  publicKey: '03DC13CBBF29765C7745578D9E091280522F37684EF0E400B86B1C409BC454F1F3',
  privateKey: '353ED4C9DB2A13B8EB319618EAF7A61DC5AB74AF79020C9C21D06E768A6D3E24',
};







export const ACCOUNT_1 = {
  accountHash:
    'fbba1c5277d27546060925b80c780aa708cf12bcb8a4c0c34ce22af15de7ac9c',
  publicKey:
    '021a08bb34f8a5d978ac8dbecabd4b0e8edf2e1cf1800bade6de3baa4dddfe3449',
  privateKey:
    '06a8f3e2bf2d9104c61af9ea0d72e36bab0730ecccf94817e5b746332d849c0b'
};

export const ACCOUNT_2 = {
  accountHash:
    '53eb4139304aa9c5087daaf252c8644a883e515f9bde9d0d65fa986537bcab95',
  publicKey:
    '03edf27fbbb5c6b42f3139b18933b47e9c6d3e0c3077ac41f4aa47bbb6eebc3dbc',
  privateKey:
    'cb519717178f4e7bd1e7625748f5294b43584703a93ebdb9718289d5f8ac343b'
};

export const OWNER_1 = {
  accountHash:
    'e3315d010f31cc3c682c091628fd6c1704d9ae7b6bc04846816baf83b1bb0f2b',
  publicKey:
    '03d5dadb76416f01b5df715b87aaf7ebf5b86f71b9d1d97d100f52bc4b113c05eb',
  privateKey:
    '5077327556cd716d1167f7cc513b38672a1a4edf94df846a790a7d4c26b7c2d5',
  xpub:
    'xpub661MyMwAqRbcFn97q1KxsbXyXJQ49bzPqcisB2YHoWShkJPXXexd12pdgRTczC6rDhFKNV7PAgMRWqGQtoh9tmgLgFdQGrjciEYKsNwfzt1',
  xprv:
    'xprv9s21ZrQH143K3J4eiynxWTbEyGZZk9GYUPoGNe8gFAuisW4Nz7eNTEW9q9YiMxDa7KtpZM5hoVtUdKYu2dMyw3MsHHpw935RApMzgPZ4Qw2',
};

export const OWNER_2 = {
  accountHash:
    'ed9ac139ff5cc4f76072e7086865bae8409a3944f3259a4dc4b05c99dba400a5',
  publicKey:
    '03c975dd4c0009d130c01e599736ed6e70e61c779923b62c3ddaff1c3038de3125',
  privateKey:
    'f38a76f2c99593cdf2edc7c2d80ed791c1b628837dbd14dd4d58ac8d4b8a16e2'
};

export const OWNER_3 = {
  accountHash: 'cd1eac3bc52716f3177bc7f9c5d7de10b98c74c6c1ace2c874e0e09f47469023',
  publicKey: '03DC13CBBF29765C7745578D9E091280522F37684EF0E400B86B1C409BC454F1F3',
  privateKey: '353ED4C9DB2A13B8EB319618EAF7A61DC5AB74AF79020C9C21D06E768A6D3E24',
};

export const GAS_LIMIT = '123';

export const FEE = { gasLimit: '10000000', gasPrice: '10' };

export const INVALID_SHORT_KEYPAIR_KEY = '82A34E';

export const INVALID_LONG_KEYPAIR_PRV = ACCOUNT_FROM_SEED.privateKey + 'F1';

export const INVALID_PRIVATE_KEY_ERROR_MESSAGE = 'Unsupported private key';

export const INVALID_PUBLIC_KEY_ERROR_MESSAGE = 'Unsupported public key:';

export const VALID_ADDRESS = '608e43c3bb3f44200ec59d71d461d3e5aa4e823c595848a5d280f831ce8de302';

export const INVALID_ADDRESS = '608e43c3gg3f44200ec59Y7ZXC461d3e5aa4e823c595848a5d280f831ce8de302';

export const INVALID_ADDRESS_EMPTY = '';

export const INVALID_ADDRESS_EMPTY_W_SPACES = '   ';

export const INVALID_KEYPAIR_PRV = new KeyPair({
  prv: '8CAA00AE63638B0542A304823D66D96FF317A576F692663DB2F85E60FAB2590C',
});

export const KEYPAIR_PRV = new KeyPair({
  prv: '353ED4C9DB2A13B8EB319618EAF7A61DC5AB74AF79020C9C21D06E768A6D3E24',
});

export const WALLET_SIGNED_TRANSACTION = '';

export const SECP256K1_PREFIX = '02';