import { createMemoryClient } from '@tevm/memory-client';
import { ethers } from 'ethers';
import { DNSProver } from '@ensdomains/dnsprovejs';
import { createScript } from 'tevm/contract';
import { formatAbi } from 'tevm/utils';

import { abi, bytecode, deployedBytecode } from './DNSSECImpl.json';

const domain = 'gregskril.com';
const qType  = 'TXT';

const prover = DNSProver.create('https://cloudflare-dns.com/dns-query');
const result = await prover.queryWithProof(qType, domain);
const ret = Array.prototype
  .concat(result.proofs, [result.answer])
  .map((entry) => ({
    rrset: entry.toWire(),
    sig: entry.signature.data.signature,
  }));

const rrsBytes = ret.map(({ rrset, sig }) => ({
  rrset: ethers.hexlify(rrset),
  sig: ethers.hexlify(sig),
}));

const script = createScript({
  name: 'DNSSECImpl',
  humanReadableAbi: formatAbi(abi),
  bytecode: `0x${bytecode.replace('0x', '')}`,
  deployedBytecode: `0x${deployedBytecode.replace('0x', '')}`,
});

const memoryClient = createMemoryClient();

const { verifyRRSet }: any = script.read;
const response = await memoryClient.script(
  verifyRRSet(rrsBytes, (Date.now() / 1000).toFixed(0))
);
console.log(response);

/**
 *
 * SignatureTypeMismatch(uint16,uint16)	0xa6ff8a8a
 * InvalidClass(uint16)	0x98a5f31a
 * InvalidLabelCount(bytes,uint256)	0xe861b2bd
 * InvalidProofType(uint16)	0x61529e87
 * InvalidRRSet()	0xcbceee6f
 * InvalidSignerName(bytes,bytes)	0xeaafc59b
 * NoMatchingProof(bytes)	0x06cde0f3
 * ProofNameMismatch(bytes,bytes)	0xd700ae7e
 * SignatureExpired(uint32,uint32)	0xa784f87e
 * SignatureNotValidYet(uint32,uint32)	0xbd41036a
 *
 */
