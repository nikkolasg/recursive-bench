use anyhow::Result;
use plonky2::plonk::{
    circuit_data::CircuitConfig,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use recursive_bench::plonky2 as plonkuit;
use serde::Serializer;
use std::time::{Duration, Instant};

fn duration_to_ms<S>(x: &Duration, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u64(x.as_millis() as u64)
}
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub enum Backend {
    #[default]
    Plonky,
    Nova,
}

#[derive(Clone, Default, serde::Serialize)]
pub struct BenchParams {
    pub backend: Backend,
    pub length: usize,
    pub degree: usize,
}

#[derive(Clone, Default, serde::Serialize)]
pub struct BenchResult {
    #[serde(flatten)]
    pub params: BenchParams,
    #[serde(serialize_with = "duration_to_ms")]
    pub recursion_time: Duration,
    #[serde(serialize_with = "duration_to_ms")]
    pub final_snark_time: Duration,
    // prover_time = recursion_time + final snark time
    // In case of Plonk2 the final_snark_time should be the same as individual recursive step
    #[serde(serialize_with = "duration_to_ms")]
    pub prover_time: Duration,
    #[serde(serialize_with = "duration_to_ms")]
    pub verification_time: Duration,
    pub proof_size: usize,
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn plonky_recursion_benchmark(p: BenchParams) -> Result<BenchResult> {
    let mut res = BenchResult {
        params: p,
        ..BenchResult::default()
    };
    println!("[+] Plonky2: Generate a first proof");
    // we generate a first proof to verify
    // TODO: Should be a satisfying empty proof to mimick IVC style - idk if it exists in plonky2 yet
    let input1 = hex::decode("600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000").unwrap();
    let config = CircuitConfig::standard_recursion_config();
    let start = Instant::now();
    let inner = plonkuit::generate_sha256_proof::<F, C, D>(&config, input1.clone())?;
    let mut last_proof = inner;
    println!(
        "[+] Plonky2: Generate {} recursive proofs",
        res.params.length
    );
    for i in 0..res.params.length {
        let start = Instant::now();
        last_proof =
            plonkuit::recursive_sha(&last_proof, &config, input1.clone(), res.params.degree)?;
        if i == res.params.length - 1 {
            res.final_snark_time = start.elapsed();
        } else {
            res.recursion_time += start.elapsed();
        }
    }
    res.prover_time = start.elapsed();
    println!("[+] Plonky2: Serializing the final proof");
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &last_proof.0).unwrap();
    let compressed_proof = encoder.finish().unwrap();
    res.proof_size = compressed_proof.len();

    println!("[+] Plonky2: Verifying the final proof");
    let start = Instant::now();
    assert!(last_proof.1.verify(last_proof.0).is_ok());
    res.verification_time = start.elapsed();
    Ok(res)
}

use flate2::{write::ZlibEncoder, Compression};
use recursive_bench::nova as novuit;
type G1 = pasta_curves::pallas::Point;
type F1 = pasta_curves::pallas::Scalar;
type G2 = pasta_curves::vesta::Point;
type F2 = pasta_curves::vesta::Scalar;

type C1 = novuit::HashChainCircuit<<G1 as Group>::Scalar>;
type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;

use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    PublicParams, RecursiveSNARK,
};

pub fn nova_recursion_benchmark(p: BenchParams) -> Result<BenchResult> {
    let mut res = BenchResult {
        params: p.clone(),
        ..BenchResult::default()
    };
    let v0 = F1::from(10);
    let chain = novuit::HashChain::generate(v0, p.length as u64).unwrap();
    let first_step = chain.entry(0).unwrap();
    let primary_circuit = novuit::HashChainCircuit::new(first_step.clone());
    let secondary_circuit = TrivialTestCircuit::default();
    let pp = PublicParams::<G1, G2, C1, C2>::setup(&primary_circuit, &secondary_circuit);

    let z0_primary = vec![F1::from(first_step.index), first_step.input];
    let z0_secondary = vec![F2::from(2)];

    println!("[+] Nova: Initializing the folding structure...");
    let start = Instant::now();
    let mut rs = RecursiveSNARK::new(
        &pp,
        &primary_circuit,
        &secondary_circuit,
        z0_primary.clone(),
        z0_secondary.clone(),
    );

    println!("[+] Nova: Performing {} folding steps...", p.length);
    for i in 0..p.length {
        let start = Instant::now();
        let chain_node = chain.entry(i).unwrap();
        // we give the advice corresponding to step i
        let circuit = novuit::HashChainCircuit::new(chain_node.clone());
        assert!(rs
            .prove_step(
                &pp,
                &circuit,
                &secondary_circuit,
                z0_primary.clone(),
                z0_secondary.clone()
            )
            .is_ok());
        res.recursion_time += start.elapsed();
    }
    debug_assert!(rs.verify(&pp, p.length, &z0_primary, &z0_secondary).is_ok());

    type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
    type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<G1, EE1>;
    type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<G2, EE2>;

    println!("[+] Nova: Generating final SNARK using Spartan with IPA-PC...");
    let (pk, vk) = nova_snark::CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let compressed_snark = {
        let start = Instant::now();
        let final_proof = nova_snark::CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &rs);
        debug_assert!(final_proof.is_ok());
        res.final_snark_time = start.elapsed();
        final_proof.unwrap()
    };
    res.prover_time += start.elapsed();

    println!("[+] Nova: Serializing a compressed version of final SNARK...");
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    res.proof_size = compressed_snark_encoded.len();

    // verify the compressed SNARK
    println!("[+] Nova: Verifying the final proof...");
    let start = Instant::now();
    let is_valid_proof = compressed_snark.verify(&vk, p.length, z0_primary, z0_secondary);
    assert!(is_valid_proof.is_ok());
    res.verification_time = start.elapsed();
    Ok(res)
}

/// MAIN CLI PART
///
use clap::Parser;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run full benchmark or short version - by default is full
    #[arg(short, long, default_value_t = false)]
    short: bool,
}
struct Experiment {
    params: BenchParams,
    bench: fn(BenchParams) -> Result<BenchResult>,
}

fn generate_experiments(args: Args) -> Vec<Experiment> {
    // [ (length , degree) ] pairs
    let params = if args.short {
        println!("--- Running the SHORT version of the benchmark ---\n");
        vec![(3, 1)]
    } else {
        println!("--- Running the LONG version of the benchmark ---\n");
        vec![(3, 1), (8, 1), (15, 1), (20, 1)]
    };

    // create a nova and a plonky2 experiment for each parameter set
    params
        .iter()
        .flat_map(|(l, d)| {
            let length = *l as usize;
            let degree = *d as usize;
            let plonky_exp = Experiment {
                params: BenchParams {
                    backend: Backend::Plonky,
                    length,
                    degree,
                },
                bench: plonky_recursion_benchmark,
            };
            let nova_exp = Experiment {
                params: BenchParams {
                    backend: Backend::Nova,
                    length,
                    degree,
                },
                bench: nova_recursion_benchmark,
            };
            [plonky_exp, nova_exp]
        })
        .collect::<Vec<_>>()
}
fn main() -> Result<()> {
    let mut wtr = csv::Writer::from_writer(std::fs::File::create("bench.csv")?);
    let args = Args::parse();
    let experiments = generate_experiments(args);
    for exp in experiments {
        // Run it and write to csv
        let res = (exp.bench)(exp.params)?;
        print!("");
        wtr.serialize(res)?;
    }
    Ok(())
}
