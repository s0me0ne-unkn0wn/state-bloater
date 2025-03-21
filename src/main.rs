mod mythos;

use sp_core::Pair;
use sp_core::keccak_256;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use subxt::backend::rpc::RpcClient;
use subxt::ext::subxt_rpcs::LegacyRpcMethods;
use subxt::Config;

use sha3::{Keccak256, Digest};
use sp_core::ecdsa;
use sp_core::crypto;
use subxt::utils::H160;
// use subxt::Config;
use subxt::tx::Signer;

const SENDER_SEED: &str = "//Sender";

#[derive(
	Eq, PartialEq, Copy, Clone, Encode, Decode, MaxEncodedLen, Default, PartialOrd, Ord, Hash
)]
pub struct AccountId20(pub [u8; 20]);

impl_serde::impl_fixed_hash_serde!(AccountId20, 20);

impl std::fmt::Display for AccountId20 {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let address = hex::encode(self.0).trim_start_matches("0x").to_lowercase();
		let address_hash = hex::encode(keccak_256(address.as_bytes()));

		let checksum: String =
			address
				.char_indices()
				.fold(String::from("0x"), |mut acc, (index, address_char)| {
					let n = u16::from_str_radix(&address_hash[index..index + 1], 16)
						.expect("Keccak256 hashed; qed");

					if n > 7 {
						// make char uppercase if ith character is 9..f
						acc.push_str(&address_char.to_uppercase().to_string())
					} else {
						// already lowercased
						acc.push(address_char)
					}

					acc
				});
		write!(f, "{checksum}")
	}
}

impl core::fmt::Debug for AccountId20 {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{:?}", H160(self.0))
	}
}

impl From<[u8; 20]> for AccountId20 {
	fn from(bytes: [u8; 20]) -> Self {
		Self(bytes)
	}
}

impl From<AccountId20> for [u8; 20] {
	fn from(value: AccountId20) -> Self {
		value.0
	}
}

impl From<H160> for AccountId20 {
	fn from(h160: H160) -> Self {
		Self(h160.0)
	}
}

impl From<AccountId20> for H160 {
	fn from(value: AccountId20) -> Self {
		H160(value.0)
	}
}

impl std::str::FromStr for AccountId20 {
	type Err = &'static str;
	fn from_str(input: &str) -> Result<Self, Self::Err> {
		H160::from_str(input).map(Into::into).map_err(|_| "invalid hex address.")
	}
}

type EthSignature = [u8; 65];

pub enum MythicalConfig {}

impl Config for MythicalConfig {
    type Hash = subxt::utils::H256;
    type AccountId = AccountId20;
    type Address = AccountId20;
    type Signature = EthSignature;
    type Hasher = subxt::config::substrate::BlakeTwo256;
    type Header = subxt::config::substrate::SubstrateHeader<u32, subxt::config::substrate::BlakeTwo256>;
    type ExtrinsicParams = subxt::config::SubstrateExtrinsicParams<Self>;
    type AssetId = u32;
}

pub struct EthereumSigner {
	account_id: AccountId20,
	signer: ecdsa::Pair,
}

impl sp_runtime::traits::IdentifyAccount for EthereumSigner {
	type AccountId = AccountId20;
	fn into_account(self) -> Self::AccountId {
		self.account_id
	}
}

impl From<ecdsa::Pair> for EthereumSigner
// where C::AccountId: AccountId20
{
	fn from(pair: ecdsa::Pair) -> Self {
		let decompressed = libsecp256k1::PublicKey::parse_compressed(&pair.public().0)
			.expect("Wrong compressed public key provided")
			.serialize();
		let mut m = [0u8; 64];
		m.copy_from_slice(&decompressed[1..65]);
		Self { account_id: H160::from_slice(&Keccak256::digest(m).as_slice()[12..32]).into(),
			signer: pair
		}
	}
}

impl Signer<MythicalConfig> for EthereumSigner {
    fn account_id(&self) -> <MythicalConfig as Config>::AccountId {
        self.account_id
    }

    fn sign(&self, signer_payload: &[u8]) -> <MythicalConfig as Config>::Signature {
        let hash = keccak_256(signer_payload);
        let wrapped = libsecp256k1::Message::parse_slice(&hash).unwrap();
        self.signer.sign_prehashed(&wrapped.0.b32()).try_into().expect("Signature has correct length")
    }
}

impl From<AccountId20> for mythos::api::runtime_types::account::AccountId20 {
    fn from(value: AccountId20) -> Self {
        Self(value.0)
    }
}

pub fn derive_accounts<T>(from: usize, n: usize, seed: String) -> Vec<T>
where T: Pair + Send + 'static
{
	let t = std::cmp::min(
		n,
		std::thread::available_parallelism().unwrap_or(1usize.try_into().unwrap()).get(),
	);

	let mut tn = (0..t).cycle();
	let mut tranges: Vec<_> = (0..t).map(|_| Vec::new()).collect();
	(from..from + n).for_each(|i| tranges[tn.next().unwrap()].push(i));
	let mut threads = Vec::new();

	tranges.into_iter().for_each(|chunk| {
		let seed = seed.clone();
		threads.push(std::thread::spawn(move || {
			chunk
				.into_iter()
				.map(move |i| {
					let derivation = format!("{seed}{i}");
					<T as Pair>::from_string(&derivation, None).unwrap()
				})
				.collect::<Vec<_>>()
		}));
	});

	threads
		.into_iter()
		.map(|h| h.join().unwrap())
		.flatten()
		.collect()
}

const BATCH_BY: usize = 100;
use crate::mythos::api::runtime_types::mainnet_runtime::RuntimeCall;
use crate::mythos::api::runtime_types::pallet_balances::pallet::Call as BalancesCall;
use crate::mythos::api::runtime_types::pallet_nfts::pallet::Call as NftsCall;
use crate::mythos::api::runtime_types::runtime_common::IncrementableU256;
use crate::mythos::api::runtime_types::primitive_types::U256;
use subxt_signer::ecdsa::Keypair;
use subxt_signer::SecretUri;
use std::str::FromStr;
use subxt::config::DefaultExtrinsicParamsBuilder as ParamsBuilder;

impl From<subxt_signer::eth::PublicKey> for AccountId20 {
    fn from(value: subxt_signer::eth::PublicKey) -> Self {
        Self(value.0[..].try_into().unwrap())
    }
}

use clap::Parser;

#[derive(Parser, Debug)]
// #[command(author, version, about, long_about = None)]
#[derive(clap::ValueEnum, Clone)]
/// The type of operation to perform.
pub enum OperationType {
    /// Account-related operations like transferring funds
    Account,
    /// NFT-related operations like minting and burning
    Nft,
}

#[derive(Parser, Debug)]
struct Args {
    /// From which account to start deriving
    #[arg(long, short, default_value_t = 0usize)]
    from: usize,

    /// Type of operation to perform
    #[arg(long, short, value_enum)]
    type_: OperationType,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	env_logger::init_from_env(
		env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
	);

    let args = Args::parse();

    let rpc_client = RpcClient::from_url("ws://127.0.0.1:9933").await?;
    let rpc = LegacyRpcMethods::<MythicalConfig>::new(rpc_client.clone());
    let api = subxt::OnlineClient::<MythicalConfig>::from_rpc_client(rpc_client).await?;

    let signer = EthereumSigner::from(ecdsa::Pair::from_seed(&subxt_signer::eth::dev::alith().secret_key()));

    match args.type_ {
        OperationType::Account => {
            let send_accs: Vec<_> = derive_accounts::<ecdsa::Pair>(args.from, 3000, SENDER_SEED.to_owned());
            
            for i in 0..(send_accs.len() / BATCH_BY) {
                let nonce = rpc.system_account_next_index(&signer.account_id()).await?;
                let params = ParamsBuilder::new().nonce(nonce).build();
                
                let batch_calls: Vec<_> = send_accs.iter().skip(i * BATCH_BY).take(BATCH_BY).map(|acc| 
                    RuntimeCall::Balances(BalancesCall::transfer_keep_alive {
                        dest: EthereumSigner::from(acc.clone()).account_id().into(),
                        value: 10_000_000_000_000_000,
                    })
                ).collect();

                let res = api.tx().sign_and_submit(
                    &mythos::api::tx().utility().batch(batch_calls),
                    &signer,
                    params
                ).await;
                if res.is_err() {
                    println!("{}", args.from + i * BATCH_BY);
                    eprintln!("Error: {:?}", res.err().unwrap());
                    return Ok(());
                }
            }
            println!("{}", args.from + send_accs.len());
        },
        OperationType::Nft => {
            for i in 0..30 { // 3000/100 = 30 batches to match the account operation count
                let nonce = rpc.system_account_next_index(&signer.account_id()).await?;
                let params = ParamsBuilder::new().nonce(nonce).build();
                
                let batch_calls: Vec<_> = (0..BATCH_BY).map(|_| {
                    RuntimeCall::Nfts(NftsCall::mint {
                        collection: IncrementableU256(U256([0, 0, 0, 0])),
                        maybe_item: None,
                        mint_to: signer.account_id().into(),
                        witness_data: None,
                    })
                }).collect();

                let res = api.tx().sign_and_submit(
                    &mythos::api::tx().utility().batch(batch_calls),
                    &signer,
                    params
                ).await;
                if res.is_err() {
                    println!("{}", args.from + i * BATCH_BY);
                    eprintln!("Error: {:?}", res.err().unwrap());
                    return Ok(());
                }
            }
            println!("{}", args.from + 3000); // Keep the same output format
        }
    }

    Ok(())
}
