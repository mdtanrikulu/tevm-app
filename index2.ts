import { createMemoryClient } from '@tevm/memory-client'
import { DNSProver } from '@ensdomains/dnsprovejs';
import { DNSSECImpl } from '../ENS/ens-contracts/contracts/dnssec-oracle/DNSSECImpl.sol'

const domain = 'luc.cash';

const prover = DNSProver.create('https://cloudflare-dns.com/dns-query');
const result = await prover.queryWithProof('TXT', domain);
const ret = Array.prototype
  .concat(result.proofs, [result.answer])
  .map((entry) => ({
    rrset: entry.toWire(),
    sig: entry.signature.data.signature,
  }));


const memoryClient = createMemoryClient({})

const response = await memoryClient.script(DNSSECImpl.read.verifyRRSet(ret))
console.log(response);
