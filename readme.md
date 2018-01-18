# Extracting a CFG
To extract a CFG, we first need to identify conditional branches. Conditional branches that are taken for certain (jz when zf == 0) have to be ignored, as the other dest can be invalid code. However, there needs to be some care taken regarding initial conditions when loops are involved, for-example the following code's `label_2` may be ignored if initial conditions are not updated, through discovery of new blocks:

        xor eax, eax
    label_1:
        jnz label_2
        inc eax
        jmp label_1
    label_2:

So this becomes abstract intrepretation. In order to update initial conditions properly, we re-execute new blocks if the initial conditions have not yet reached a fixed-point. In order to save time, we use BFS so both branches of a conditional are run first before the remaining code is run.

In order to handle jge/jle, and fixed locations in stack/memory, our constraint involves constants with disjunctions, where `esp_0 + const` is also considered a constant.

## Expression manipulations which hinder abstract interpretation
It is possible where are some cases where there are expressions like `eax_0 + eax_1 - eax_1 - eax_0`. This can hinder constant analysis.

In this case, we may be tempted to use symbolic execution rather than block simplification for performance reasons. To be complete, we need to implement all operations symbolically, then evaluate constraints at the end of the block. But this has some disadvantages:

- The expressions may be large, even if some sub-expressions are the same variable, this may be expensive.
- Coding new simplifications duplicates work from block simplification.
- If there is a need for coding constraint-based block simplification (e.g. range constraints making some parts 0 to allow for further transforms), then there is probably also a need for constraint-based expression simplification, which duplicates work.
- The symbolic evaluator restricts how the stack/memory is implemented (e.g. that they are separated), instead of leaving this up to the constraint class.

A mitigation to the performance problem is to instead perform block simplification every time there is an unknown predicate, which should not occur often.

## API Calls
API calls end a block to facilitate block-by-block deobfuscation.

## Functions
In order to identify functions, we look at when the constraints start having a different eip at the start of a block than before. In order to then identify where the call came from, we can perform taint analysis to see which operation tainted eip.

### Inlining
Some functions are useless and may be called multiple times, so in order to facilitate analysis (both constraint propagation and block deobfuscation), we allow inlining.

# De-obfuscation after the CFG is extracted
De-obfuscation is done on the CFG, as well as block-by-block.

# Self-modifying code
The analysis supposes the program does not modify itself.

Decryption loops can be emulated outside of the static analyzer.

For self-modifying conditions, we will provide an api to let the user hook addresses so fixed code can become some user-specified code to be handed to the analyzer.

# Other tools
Radeco only works on linux and is not aimed particularly at de-obfuscation. For convenience of python we code own ssa form/simplification routines.

# Visualization
- Comparison with IDA: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.3748&rep=rep1&type=pdf
