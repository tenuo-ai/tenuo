// Deliberately fails compilation: original defining-module bypasses are gone.
import {PaymentClient, client, executeTransfer} from '../src/payment.js';
new PaymentClient().transfer('merchant', 200);
client.transfer('merchant', 200);
executeTransfer('merchant', 200);
