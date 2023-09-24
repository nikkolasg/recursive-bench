use bellpepper::gadgets::Assignment;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use eyre::Result;
use ff::PrimeField as Scalar;
use generic_array::typenum::U2;
use neptune::poseidon::PoseidonConstants;

use arecibo::traits::circuit::StepCircuit;

#[derive(Clone)]
pub struct HashChainCircuit<S: Scalar> {
    // we only do one iteration in one step
    iteration: ChainNode<S>,
}

impl<S> HashChainCircuit<S>
where
    S: Scalar,
{
    #[allow(dead_code)]
    pub fn new(iteration: ChainNode<S>) -> HashChainCircuit<S> {
        Self { iteration }
    }
}

impl<S> StepCircuit<S> for HashChainCircuit<S>
where
    S: Scalar,
{
    fn arity(&self) -> usize {
        2
    }

    // Expected state
    //  - index
    //  - input
    // Expected advice/witness
    //  - expected output = H ( index || input )
    fn synthesize<CS: ConstraintSystem<S>>(
        &self,
        cs: &mut CS,
        io: &[AllocatedNum<S>],
    ) -> Result<Vec<AllocatedNum<S>>, SynthesisError> {
        let constants: PoseidonConstants<S, U2> = PoseidonConstants::new();
        let i = io[0].clone();
        let v_i = io[1].clone();
        // sanity checks
        //{
        //    let computed_i = &S::from(self.iteration.index);
        //    if i.get_value().get()? != computed_i;
        //    //if state_i == computed_i {
        //    //    println!("state_i == computed_i");
        //    //} else {
        //    //    println!("state_i {:?} != computed_i {:?}",state_i, computed_i);
        //    //}
        //    //assert_eq!( computed_i, state_i, "mismatch index {:?} vs {:?}", computed_i,state_i);
        //    //assert_eq!(&self.iteration.input, v_i.get_value().get()?);
        //}
        //let output = neptune::circuit2::poseidon_hash_allocated(
        let computed_output = neptune::circuit::poseidon_hash(
            // H ( i || v_i )
            &mut cs.namespace(|| "round"),
            vec![i.clone(), v_i],
            &constants,
        )?;
        // NOTE: we could enforce that the output of the sha256 circuit is equal to an advice value as in the following
        // However, this is not necessary as Nova guarantees the input/output consistency, so as long as we give as output
        // "computed_output", then we're sure that at the next step we're gonna get the same value. The prover can not
        // cheat by inserting random values and we know by construction that computed_output is correct since constraints
        // have been enforced.
        // By contrast, in the minroot example (https://github.com/microsoft/Nova/blob/main/examples/minroot.rs#L105),
        // the new state x_{i+1} is given as advice because it is necessary to enable efficient verification: one simply
        // computes its 5th power intead of the 5th root of the input. The point is that this advice is not necessary for
        // soundness but simply for efficiency.
        // let given_output =
        // AllocatedNum::alloc(cs.namespace(|| "H advice"), || Ok(self.iteration.hash))?;
        //cs.enforce(
        //    || "expected hash output",
        //    |lc| lc + computed_output.get_variable(),
        //    |lc| lc + CS::one(),
        //    |lc| lc + given_output.get_variable(),
        //);

        // Here we do need to enforce the constraints because otherwise i_new could be anything.
        let i_new = AllocatedNum::alloc(cs.namespace(|| "i + 1"), || {
            Ok(*i.get_value().get()? + S::ONE)
        })?;
        cs.enforce(
            || "correct increment",
            |lc| lc + i.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + i_new.get_variable(),
        );

        Ok(vec![i_new, computed_output])
    }
}

#[derive(Clone)]
pub struct ChainNode<S: Scalar> {
    pub input: S,
    pub index: u64,
    pub hash: S,
}

#[allow(dead_code)]
pub struct HashChain<S: Scalar>(pub(crate) Vec<ChainNode<S>>);

impl<S> HashChain<S>
where
    S: Scalar,
{
    #[allow(dead_code)]
    pub fn generate(v0: S, steps: u64) -> Result<Self> {
        //let arity = 2;
        //let constants: neptune::PoseidonConstants<Fp, U2> =
        // neptune::PoseidonConstants::new_constant_length(preimage_set_length);
        let mut chain = Vec::new();
        let constants: PoseidonConstants<S, U2> = PoseidonConstants::new();
        let mut h = neptune::Poseidon::<S, U2>::new(&constants);
        let mut v = v0;
        for i in 0..steps {
            h.reset();
            let idx = S::from(i + 1);
            h.input(idx)?;
            h.input(v)?;
            let result = h.hash();
            let node = ChainNode {
                input: v,
                index: i + 1,
                hash: result,
            };
            chain.push(node);
            v = result;
        }
        Ok(HashChain(chain))
    }

    // 0-based indexed
    // TODO iterator trait
    #[allow(dead_code)]
    pub fn entry(&self, step: usize) -> Option<ChainNode<S>> {
        self.0.get(step).cloned()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use pasta_curves::pallas::Scalar;
    #[test]
    fn hashchain_validate() {
        let v0 = Scalar::from(3);
        let t = 10;
        let chain = HashChain::generate(v0, t).unwrap();
        assert!(chain.0.len() == t as usize);
        for i in 1..t - 1 {
            assert!(chain.0[(i - 1) as usize].index + 1 == chain.0[i as usize].index);
        }
    }

    type G1 = pasta_curves::pallas::Point;
    type F1 = pasta_curves::pallas::Scalar;
    type G2 = pasta_curves::vesta::Point;
    type F2 = pasta_curves::vesta::Scalar;

    type C1 = HashChainCircuit<<G1 as Group>::Scalar>;
    type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;

    use arecibo::{
        traits::{circuit::TrivialTestCircuit, Group},
        PublicParams, RecursiveSNARK,
    };

    #[test]
    fn circuit_step() {
        let v0 = F1::from(10);
        let num_steps = 10;
        let chain = HashChain::generate(v0, num_steps).unwrap();
        let first_step = chain.entry(0).unwrap();
        let primary_circuit = HashChainCircuit::new(first_step.clone());
        let secondary_circuit = TrivialTestCircuit::default();
        let pp =
            PublicParams::<G1, G2, C1, C2>::new(&primary_circuit, &secondary_circuit, None, None);

        let z0_primary = vec![F1::from(first_step.index), first_step.input];
        let z0_secondary = vec![F2::from(2)];

        let mut rs = RecursiveSNARK::new(
            &pp,
            &primary_circuit,
            &secondary_circuit,
            z0_primary.clone(),
            z0_secondary.clone(),
        );

        for i in 0..num_steps {
            let chain_node = chain.entry(i as usize).unwrap();
            // we give the advice corresponding to step i
            let circuit = HashChainCircuit::new(chain_node.clone());
            assert!(rs
                .prove_step(
                    &pp,
                    &circuit,
                    &secondary_circuit,
                    z0_primary.clone(),
                    z0_secondary.clone()
                )
                .is_ok());
        }

        assert!(rs
            .verify(&pp, num_steps as usize, &z0_primary, &z0_secondary)
            .is_ok());
    }
}
