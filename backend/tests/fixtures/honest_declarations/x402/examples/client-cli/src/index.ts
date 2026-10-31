import { Keypair } from '@stellar/stellar-sdk';
import { wrapFetchWithPayment } from '@x402/fetch';
const signer = Keypair.fromSecret(process.env.STELLAR_PRIVATE_KEY!);
const pay = wrapFetchWithPayment(fetch, signer);
export const weather = () => pay(process.env.SERVER_URL + '/weather');
