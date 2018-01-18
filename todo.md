
- handle proc calls (analyze function if not already analyzed, and re-run functions which are in-lined), it makes more sense to update the constraints in _explore_block() when there is an address collision and check eip there, then split into function if necessary
- Allow manually specifying functions to be inlined. This is necessary in order to prevent duplicate code blocks from being run.
- To better locate where blocks are and what we have missing do coverage in js (draw as canvas), also have a list that lists exactly those ranges
- Allow clicking blocks to highlight the addresses covered, and also highlight its corresponding list of addresses
- Present cfg in javascript, the result would look something like ida's analysis and generate a graph, with a list of functions on left panel and accesses on top
- The user should deal with self-modifying code, in order to do this, add an instruction change hook, that whenever this instruction is encountered, it will be changed to user-specified esil