import { AssembledTransaction, Operation, xdr, Address, Keypair } from "@stellar/stellar-sdk";
export function register(server, contract, wallet, stub, ip) {
  for (const func of contract.spec.funcs()) {
    const func_name = func.name().toString();
    server.tool(func_name, func.doc().toString(), {}, async (params) => {
      const at = await AssembledTransaction.buildWithOp(
        Operation.invokeHostFunction({
          func: xdr.HostFunction.hostFunctionTypeInvokeContract(new xdr.InvokeContractArgs({
            contractAddress: Address.fromString(contract.options.contractId).toScAddress(),
            functionName: func_name,
            args: Object.values(params)
          }))
        }),
        contract.options
      );
      if (at.isReadCall) return { content: [{ type: "text", text: "read" }] };
      const [address, sk] = await stub.getAddress(ip);
      await wallet.sign(at, { keypair: Keypair.fromSecret(sk) });
      const res = await server.send(at);
      return { content: [{ type: "text", text: String(res) }] };
    });
  }
}
