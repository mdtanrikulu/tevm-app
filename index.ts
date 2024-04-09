import { createMemoryClient } from '@tevm/memory-client';
import { DNSProver } from '@ensdomains/dnsprovejs';
import { createScript } from 'tevm/contract';
import { formatAbi } from 'tevm/utils';

import { abi, bytecode, deployedBytecode } from './DNSSECImpl.json';

const domain = 'luc.cash';

const prover = DNSProver.create('https://cloudflare-dns.com/dns-query');
const result = await prover.queryWithProof('TXT', domain);
const ret = Array.prototype
  .concat(result.proofs, [result.answer])
  .map((entry) => ({
    rrset: entry.toWire(),
    sig: entry.signature.data.signature,
  }));


const script = createScript({
  name: 'DNSSECImpl',
  humanReadableAbi: formatAbi(abi),
  bytecode: `0x${bytecode.replace('0x', '')}`,
  deployedBytecode: `0x${deployedBytecode.replace('0x', '')}`,
});

console.log(script.read);

const memoryClient = createMemoryClient();
const response = await memoryClient.script(script.read.verifyRRSet(ret));
console.log(response);
