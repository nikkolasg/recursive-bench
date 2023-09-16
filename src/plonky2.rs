use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_crypto::hash::sha256::CircuitBuilderHashSha2;
use plonky2_crypto::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};

pub trait Sha256Circuit<F: RichField + Extendable<D>, const D: usize> {
    fn sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> Sha256Circuit<F, D> for CircuitBuilder<F, D> {
    fn sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget {
        self.hash_sha256(input)
    }
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::*;
    use plonky2_crypto::hash::sha256::WitnessHashSha2;
    use sha2::{digest::Update, Digest, Sha256};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn test_double_sha256() {
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

        // 1. build circuit once
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
