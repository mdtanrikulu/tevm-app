import { createMemoryClient } from '@tevm/memory-client';
import { DNSProver } from '@ensdomains/dnsprovejs';
import { ethers } from 'ethers';

import { createContract, createScript } from 'tevm/contract';
import { encodeDeployData, formatAbi } from 'tevm/utils';

import { abi, bytecode, deployedBytecode, args as argsDNSSECImpl } from './DNSSECImpl.json';
import { abi as abi_RSASHA1Algorithm } from './algorithms/RSASHA1Algorithm.json';
import { abi as abi_RSASHA256Algorithm } from './algorithms/RSASHA256Algorithm.json';
import { abi as abi_P256SHA256Algorithm } from './algorithms/P256SHA256Algorithm.json';

import { abi as abi_SHA1Digest } from './digests/SHA1Digest.json';
import { abi as abi_SHA256Digest } from './digests/SHA256Digest.json';
import { extractENSRecord } from './utils';

const domain = 'gregskril.com';
const qType = 'TXT';

const deployContract = (name: string, abi: any, address: any) => {
  const contract = createContract({
    name,
    humanReadableAbi: formatAbi(abi),
  }).withAddress(address);
  const addr = contract.address;
  return addr;
};

const algorithms = [
  {
    id: 5,
    addr: deployContract(
      'RSASHA1Algorithm',
      abi_RSASHA1Algorithm,
      '0x6ca8624Bc207F043D140125486De0f7E624e37A1'
    ),
  },
  {
    id: 8,
    addr: deployContract(
      'RSASHA256Algorithm',
      abi_RSASHA256Algorithm,
      '0x9D1B5a639597f558bC37Cf81813724076c5C1e96'
    ),
  },
  {
    id: 7,
    addr: deployContract(
      'RSASHA1Algorithm',
      abi_RSASHA1Algorithm,
      '0x6ca8624Bc207F043D140125486De0f7E624e37A1'
    ),
  },
  {
    id: 13,
    addr: deployContract(
      'P256SHA256Algorithm',
      abi_P256SHA256Algorithm,
      '0x0faa24e538bA4620165933f68a9d142f79A68091'
    ),
  },
];

const digests = [
  {
    id: 1,
    addr: deployContract(
      'SHA1Digest',
      abi_SHA1Digest,
      '0x9c9fcEa62bD0A723b62A2F1e98dE0Ee3df813619'
    ),
  },
  {
    id: 2,
    addr: deployContract(
      'SHA256Digest',
      abi_SHA256Digest,
      '0xCFe6edBD47a032585834A6921D1d05CB70FcC36d'
    ),
  },
];

const prover = DNSProver.create('https://cloudflare-dns.com/dns-query');
const result = await prover.queryWithProof(qType, domain);
const ret = Array.prototype
  .concat(result.proofs, [result.answer])
  .map((entry) => ({
    rrset: entry.toWire(),
    sig: entry.signature.data.signature,
  }));

const rrsBytes = ret.map(({ rrset, sig }) => [
  ethers.hexlify(rrset),
  ethers.hexlify(sig),
]);

console.log('ENS1 record', extractENSRecord(rrsBytes).at(-1));

const script = createScript({
  name: 'DNSSECImpl',
  humanReadableAbi: formatAbi(abi),
  bytecode: `0x${bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode}`,
  deployedBytecode: `0x${
    deployedBytecode.startsWith('0x')
      ? deployedBytecode.slice(2)
      : deployedBytecode
  }`,
});

const memoryClient = createMemoryClient(/*{ loggingLevel: "debug" }*/);

try {
  const callData = encodeDeployData({
    abi: script.abi,
    bytecode: script.bytecode,
    args: argsDNSSECImpl,
  })

  
  const { createdAddresses } = await memoryClient.tevmCall({
    createTransaction: true,
    data: callData
  })

  if (!createdAddresses) throw "no contract deployed";

  const addrDNSSECImpl = Array.from(createdAddresses)[0];

  await memoryClient.tevmMine();


  const ownerResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'owner',
  });
  const addrOwner = ownerResponse.data as any;

  for (let { id, addr } of digests) {
    await memoryClient.tevmContract({
      to: addrDNSSECImpl,
      abi: script.abi,
      functionName: 'setDigest',
      args: [id, addr],
      from: addrOwner,
    });
    console.log(`digest ${id} set`);
  }

  for (let { id, addr } of algorithms) {
    await memoryClient.tevmContract({
      to: addrDNSSECImpl,
      abi: script.abi,
      functionName: 'setAlgorithm',
      args: [id, addr],
      from: addrOwner,
    });
    console.log(`algorithm ${id} set`);
  }

  await memoryClient.tevmMine();

  const algoResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'algorithms',
    args: [7]
  });
  console.log("algoResponse", algoResponse);

  const anchorResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'anchors'
  });
  console.log("anchorResponse", anchorResponse);

  const response = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'verifyRRSet',
    args: [rrsBytes]
  });

  console.log(response);
} catch (error) {
  console.log('error', error);
}
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
