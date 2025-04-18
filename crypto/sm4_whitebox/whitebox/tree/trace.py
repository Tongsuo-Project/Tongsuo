from collections import defaultdict

def circuit_trace(outputs, input_order, inputs_list):
    traces = defaultdict(int)
    input_names = [bit.name() for bit in input_order]
    for n, input_values in enumerate(inputs_list):
        trace = dict(zip(input_order, input_values))
        for bit in outputs:
            bit.eval(trace)

        for bit, value in trace.items():
            value &= 1
            traces[bit] |= (value << n)
    return traces
