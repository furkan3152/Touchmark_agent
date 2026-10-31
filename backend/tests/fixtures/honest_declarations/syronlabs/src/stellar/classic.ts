import { Asset, Horizon, Keypair, Networks, Operation, TransactionBuilder } from '@stellar/stellar-sdk';

export class Classic {
  private server: Horizon.Server;
  private networkPassphrase: string;
  constructor(serverUrl: string) {
    this.server = new Horizon.Server(serverUrl);
    this.networkPassphrase = serverUrl.includes('testnet') ? Networks.TESTNET : Networks.PUBLIC;
  }

  async createPayment(params: { destination: string; amount: string; secretKey: string }) {
    const { destination, amount, secretKey } = params;
    const sourceKeypair = Keypair.fromSecret(secretKey);
    const sourceAccount = await this.server.loadAccount(sourceKeypair.publicKey());
    const transaction = new TransactionBuilder(sourceAccount, { fee: '100', networkPassphrase: this.networkPassphrase })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount }))
      .setTimeout(30)
      .build();
    transaction.sign(sourceKeypair);
    return await this.server.submitTransaction(transaction);
  }
}
