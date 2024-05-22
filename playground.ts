import { createMemoryClient } from '@tevm/memory-client';
import { DNSProver } from '@ensdomains/dnsprovejs';
import { ethers } from 'ethers';

import { createScript } from 'tevm/contract';
import { EthjsAddress, encodeDeployData, formatAbi } from 'tevm/utils';

import {
  abi,
  bytecode,
  deployedBytecode,
  args as argsDNSSECImpl,
} from './DNSSECImpl.json';
import {
  abi as abi_RSASHA1Algorithm,
  bytecode as bytecode_RSASHA1Algorithm,
  deployedBytecode as deployedBytecode_RSASHA1Algorithm,
} from './algorithms/RSASHA1Algorithm.json';
import {
  abi as abi_RSASHA256Algorithm,
  bytecode as bytecode_RSASHA256Algorithm,
  deployedBytecode as deployedBytecode_RSASHA256Algorithm,
} from './algorithms/RSASHA256Algorithm.json';
import {
  abi as abi_P256SHA256Algorithm,
  bytecode as bytecode_P256SHA256Algorithm,
  deployedBytecode as deployedBytecode_P256SHA256Algorithm,
} from './algorithms/P256SHA256Algorithm.json';

import {
  abi as abi_SHA1Digest,
  bytecode as bytecode_SHA1Digest,
  deployedBytecode as deployedBytecode_SHA1Digest,
} from './digests/SHA1Digest.json';
import {
  abi as abi_SHA256Digest,
  bytecode as bytecode_SHA256Digest,
  deployedBytecode as deployedBytecode_SHA256Digest,
} from './digests/SHA256Digest.json';
import { extractENSRecord } from './utils';

const domain = 'gregskril.com';
const qType = 'TXT';

const deployContract = (
  name: string,
  abi: any,
  bytecode: any,
  deployedBytecode: any,
  address: any
) => {
  const script = createScript({
    name,
    humanReadableAbi: formatAbi(abi),
    bytecode: `0x${bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode}`,
    deployedBytecode: `0x${
      deployedBytecode.startsWith('0x')
        ? deployedBytecode.slice(2)
        : deployedBytecode
    }`,
  }).withAddress(address);

  const callData = encodeDeployData({
    abi: script.abi,
    bytecode: script.bytecode,
    args: [],
  });
  return callData;
};

const algorithms = [
  {
    id: 5,
    callData: deployContract.bind(
      null,
      'RSASHA1Algorithm',
      abi_RSASHA1Algorithm,
      bytecode_RSASHA1Algorithm,
      deployedBytecode_RSASHA1Algorithm,
      '0x6ca8624Bc207F043D140125486De0f7E624e37A1'
    ),
  },
  {
    id: 8,
    callData: deployContract.bind(
      null,
      'RSASHA256Algorithm',
      abi_RSASHA256Algorithm,
      bytecode_RSASHA256Algorithm,
      deployedBytecode_RSASHA256Algorithm,
      '0x9D1B5a639597f558bC37Cf81813724076c5C1e96'
    ),
  },
  {
    id: 7,
    callData: deployContract.bind(
      null,
      'RSASHA1Algorithm',
      abi_RSASHA1Algorithm,
      bytecode_RSASHA1Algorithm,
      deployedBytecode_RSASHA1Algorithm,
      '0x6ca8624Bc207F043D140125486De0f7E624e37A1'
    ),
  },
  {
    id: 13,
    callData: deployContract.bind(
      null,
      'P256SHA256Algorithm',
      abi_P256SHA256Algorithm,
      bytecode_P256SHA256Algorithm,
      deployedBytecode_P256SHA256Algorithm,
      '0x0faa24e538bA4620165933f68a9d142f79A68091'
    ),
  },
];

const digests = [
  {
    id: 1,
    callData: deployContract.bind(
      null,
      'SHA1Digest',
      abi_SHA1Digest,
      bytecode_SHA1Digest,
      deployedBytecode_SHA1Digest,
      '0x9c9fcEa62bD0A723b62A2F1e98dE0Ee3df813619'
    ),
  },
  {
    id: 2,
    callData: deployContract.bind(
      null,
      'SHA256Digest',
      abi_SHA256Digest,
      bytecode_SHA256Digest,
      deployedBytecode_SHA256Digest,
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
const vm = await memoryClient._tevm.getVm();

try {
  const callData = encodeDeployData({
    abi: script.abi,
    bytecode: script.bytecode,
    args: argsDNSSECImpl,
  });

  const { createdAddresses } = await memoryClient.tevmCall({
    createTransaction: true,
    data: callData,
  });

  if (!createdAddresses) throw 'no contract deployed';
  const addrDNSSECImpl = Array.from(createdAddresses)[0];

  await memoryClient.tevmMine();

  const ownerResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'owner',
  });
  const addrOwner = ownerResponse.data as any;

  const storageBefore = await memoryClient._tevm.getAccount({
    address: addrDNSSECImpl,
    returnStorage: true,
  });
  console.log('storageBefore', storageBefore);

  for await (let { id, callData } of digests) {
    const data = callData();

    const { createdAddresses } = await memoryClient.tevmCall({
      createTransaction: true,
      data,
    });

    if (!createdAddresses) throw 'no contract deployed';
    const contractAddr = Array.from(createdAddresses)[0];

    await memoryClient.tevmMine();
    await memoryClient.tevmContract({
      to: addrDNSSECImpl,
      abi: script.abi,
      functionName: 'setDigest',
      args: [id, contractAddr],
      from: addrOwner,
    });
    await memoryClient.tevmMine();
    console.log(`digest ${id} set`);
  }

  for await (let { id, callData } of algorithms) {
    const data = callData();

    const { createdAddresses } = await memoryClient.tevmCall({
      createTransaction: true,
      data,
    });

    if (!createdAddresses) throw 'no contract deployed';

    const contractAddr = Array.from(createdAddresses)[0];
    console.log('contractAddr', id, contractAddr);

    const mempoolB = await memoryClient._tevm.getTxPool();
    const mempoolBefore = await mempoolB.getBySenderAddress(
      EthjsAddress.fromString(addrDNSSECImpl)
    );
    console.log('mempoolBefore', mempoolBefore);

    await memoryClient.tevmMine();

    const mempoolA = await memoryClient._tevm.getTxPool();
    const mempoolAfter = await mempoolA.getBySenderAddress(
      EthjsAddress.fromString(addrDNSSECImpl)
    );
    console.log('mempoolAfter', mempoolAfter);

    await memoryClient.tevmContract({
      to: addrDNSSECImpl,
      abi: script.abi,
      functionName: 'setAlgorithm',
      args: [id, contractAddr],
      from: addrOwner,
    });
    await memoryClient.tevmMine();
    console.log(`algorithm ${id} set`);
  }

  const algoResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'algorithms',
    args: [13],
  });
  console.log('algoResponse', algoResponse);

  const storageAfter = await memoryClient._tevm.getAccount({
    address: addrDNSSECImpl,
    returnStorage: true,
  });
  console.log('storageAfter', storageAfter);

  await vm.evm.runCall({
    origin: addrOwner,
    to: EthjsAddress.fromString(addrDNSSECImpl),
    value: 1n * 10n ** 18n,
  });

  const mempoolB = await memoryClient._tevm.getTxPool();
  const mempoolBefore = await mempoolB.getBySenderAddress(
    EthjsAddress.fromString(addrDNSSECImpl)
  );
  console.log('mempoolBefore', mempoolBefore);

  await memoryClient.tevmMine();

  const mempoolA = await memoryClient._tevm.getTxPool();
  const mempoolAfter = await mempoolA.getBySenderAddress(
    EthjsAddress.fromString(addrDNSSECImpl)
  );
  console.log('mempoolAfter', mempoolAfter);

  // console.log('test', test);
  const storageFinal = await memoryClient._tevm.getAccount({
    address: addrDNSSECImpl,
    returnStorage: true,
  });
  console.log('storageFinal', storageFinal);

  // const storage = await vm.stateManager.dumpStorage(EthjsAddress.fromString(addrDNSSECImpl))
  // console.log('storage', storage)

  const anchorResponse = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'anchors',
  });
  console.log('anchorResponse', anchorResponse);

  const response = await memoryClient.tevmContract({
    to: addrDNSSECImpl,
    abi: script.abi,
    functionName: 'verifyRRSet',
    args: [rrsBytes],
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
