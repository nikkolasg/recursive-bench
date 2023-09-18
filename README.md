# Benchmark on recursion Plonky vs Nova

Run with 
```
cargo run --release -- --short
```
for a quick trial and without the short flag for a longer experiment

Things to do left:
* Correctly bind the inputs and outputs of each proofs in Plonky2 version
* Do the degree. Dependency on Nova to fold multiple instance in one.