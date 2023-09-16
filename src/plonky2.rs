use anyhow::{anyhow, Context as _, Result};
use log::{info, Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_crypto::hash::sha256::CircuitBuilderHashSha2;
use plonky2_crypto::hash::sha256::WitnessHashSha2;
use plonky2_crypto::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};
use sha2::{digest::Update, Digest, Sha256};
use std::time::{Duration, Instant};

// Helper type to hold the structure needed during recursion
type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);
pub trait Sha256Circuit<F: RichField + Extendable<D>, const D: usize> {
    fn sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> Sha256Circuit<F, D> for CircuitBuilder<F, D> {
    fn sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget {
        self.hash_sha256(input)
    }
}

// Heavily inspired from  https://github.com/mir-protocol/plonky2/blob/main/plonky2/examples/bench_recursion.rs#L73
pub fn generate_sha256_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    input: Vec<u8>,
) -> Result<ProofTuple<F, C, D>> {
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // 0. create the circuit
    let target_input = builder.add_virtual_hash_input_target(2, 512);
    let target_output = builder.sha256(&target_input);
    let num_gates = builder.num_gates();

    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    let mut time_prove = Duration::new(0, 0);
    let output = Sha256::new().chain(input.clone()).finalize();

    // set input/output
    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&target_input, &input);
    pw.set_sha256_output_target(&target_output, &output);

    // generate proof
    let now = Instant::now();
    let proof = data.prove(pw).unwrap();
    time_prove += now.elapsed();

    // verify proof
    debug_assert!(data.verify(proof.clone()).is_ok());
    Ok((proof, data.verifier_only, data.common))
}

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner: &ProofTuple<F, InnerC, D>,
    config: &CircuitConfig,
) -> Result<ProofTuple<F, C, D>>
where
    // Need to ensure we can efficiently compute the hash inside the circuit
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let (inner_proof, inner_vd, inner_cd) = inner;
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let pt = builder.add_virtual_proof_with_pis(inner_cd);
    let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
    builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    builder.print_gate_counts(0);
    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&pt, inner_proof);
    pw.set_verifier_data_target(&inner_data, inner_vd);

    let mut timing = Instant::now();
    let mut tree = TimingTree::new("prove", Level::Debug);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut tree)?;
    let time_recursive_prove = timing.elapsed();

    debug_assert!(data.verify(proof.clone()).is_ok());

    Ok((proof, data.verifier_only, data.common))
}

fn recursive_sha<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner: &ProofTuple<F, InnerC, D>,
    config: &CircuitConfig,
    input: Vec<u8>,
) -> Result<ProofTuple<F, C, D>>
where
    // Need to ensure we can efficiently compute the hash inside the circuit
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let (inner_proof, inner_vd, inner_cd) = inner;
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    // 1. verify previous proof
    let pt = builder.add_virtual_proof_with_pis(inner_cd);
    let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);
    builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    builder.print_gate_counts(0);
    // 2. compute sha256
    let target_input = builder.add_virtual_hash_input_target(2, 512);
    let target_output = builder.sha256(&target_input);

    let data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    // connect proof verification inputs
    pw.set_proof_with_pis_target(&pt, inner_proof);
    pw.set_verifier_data_target(&inner_data, inner_vd);

    // connect sha256 inputs
    let output = Sha256::new().chain(input.clone()).finalize();
    pw.set_sha256_input_target(&target_input, &input);
    pw.set_sha256_output_target(&target_output, &output);

    let mut timing = Instant::now();
    let mut tree = TimingTree::new("prove", Level::Debug);
    let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut tree)?;
    let time_recursive_prove = timing.elapsed();

    debug_assert!(data.verify(proof.clone()).is_ok());

    Ok((proof, data.verifier_only, data.common))
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::*;
    use plonky2_crypto::hash::sha256::WitnessHashSha2;
    use sha2::{digest::Update, Digest, Sha256};
    use std::time::{Duration, Instant};

    use super::*;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_sha_recursion() -> Result<()> {
        // we generate a first proof to verify
        // TODO: find the "empty proof" equivalence ?
        let input1 = hex::decode("600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000").unwrap();
        let config = CircuitConfig::standard_recursion_config();
        let inner = generate_sha256_proof::<F, C, D>(&config, input1.clone())?;
        // now we can start recursively create proof that (a) verify previous proof and (b) compute sha256 iteration
        let lvl1 = recursive_sha::<F, C, C, D>(&inner, &config, input1.clone())?;
        let lvl2 = recursive_sha::<F, C, C, D>(&lvl1, &config, input1.clone())?;
        let lvl3 = recursive_sha::<F, C, C, D>(&lvl2, &config, input1.clone())?;
        Ok(())
    }

    #[test]
    fn test_simple_recursion() -> Result<()> {
        let input = hex::decode("600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000").unwrap();
        let config = CircuitConfig::standard_recursion_config();
        let inner = generate_sha256_proof::<F, C, D>(&config, input)?;
        let outer = recursive_proof::<F, C, C, D>(&inner, &config)?;
        Ok(())
    }

    #[test]
    fn test_simple_sha256() {
        let tests = [
                // 64 bytes input
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
        ];

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 0. create the circuit
        let target_input = builder.add_virtual_hash_input_target(2, 512);
        let target_output = builder.sha256(&target_input);
        let num_gates = builder.num_gates();

        let now = Instant::now();
        let data = builder.build::<C>();
        let time_build = now.elapsed();

        // 2. generate multiple ZKPs, one per test
        let mut time_prove = Duration::new(0, 0);
        for t in tests {
            let input = hex::decode(t).unwrap();
            let output = Sha256::new().chain(input.clone()).finalize();

            // set input/output
            let mut pw = PartialWitness::new();
            pw.set_sha256_input_target(&target_input, &input);
            pw.set_sha256_output_target(&target_output, &output);

            // generate proof
            let now = Instant::now();
            let proof = data.prove(pw).unwrap();
            time_prove += now.elapsed();

            // verify proof
            assert!(data.verify(proof).is_ok());
        }
        time_prove /= tests.len() as u32;
        println!(
            "single_sha256 num_gates={num_gates} time_build={time_build:?} time_prove={time_prove:?}"
        );
    }
}
